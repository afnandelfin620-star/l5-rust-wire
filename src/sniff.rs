//! Conservative streaming TLS record recognizer. No timers, no payload buffers.
//! It is NOT a TLS terminator: only record framing, the initial hello and the
//! ServerHello's negotiated version/cipher suite are inspected.
//!
//! Passthrough latches at the first encrypted record, and only after a
//! ServerHello (seen in either direction of the session) selected TLS 1.3 with
//! a 16-byte-tag AEAD suite. A chunk containing earlier handshake bytes remains
//! FULL at the transition. After the latch every record must be a TLS 1.3
//! ciphertext record (`23 03 03`, 17..=16640 bytes); its 5-byte header is still
//! followed (bodies are skipped, never scanned) so it can be masked on the wire.
//! Any violation fails the session to FULL protection permanently.
use crate::Layout;

/// TLS 1.3 TLSCiphertext: content type + AEAD tag at minimum, 2^14 + 256 at most.
const MIN_CIPHERTEXT: usize = 1 + 16;
const MAX_CIPHERTEXT: usize = 16384 + 256;

/// Outcome of the first handshake message of one direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Hello {
    #[default]
    Pending,
    /// The first handshake message is not a ServerHello (e.g. ClientHello).
    NotServer,
    /// ServerHello parsed: whether it selected TLS 1.3 with an accepted suite.
    Server(bool),
}

/// Streaming ServerHello parser over handshake-record bodies. Reads only the
/// fields it needs into a 4-byte buffer; everything else is skipped.
struct HelloScan {
    step: u8,
    need: usize,
    got: usize,
    skip: bool,
    buf: [u8; 4],
    msg_left: usize,
    ext_left: usize,
    cipher: u16,
    version: u16,
    result: Hello,
}
impl Default for HelloScan {
    fn default() -> Self {
        Self {
            step: 0,
            need: 4,
            got: 0,
            skip: false,
            buf: [0; 4],
            msg_left: 0,
            ext_left: 0,
            cipher: 0,
            version: 0,
            result: Hello::Pending,
        }
    }
}
impl HelloScan {
    fn feed(&mut self, mut data: &[u8]) {
        while self.result == Hello::Pending && !data.is_empty() {
            let n = (self.need - self.got).min(data.len());
            if self.step != 0 {
                if n > self.msg_left {
                    self.result = Hello::Server(false);
                    return;
                }
                self.msg_left -= n;
            }
            if !self.skip {
                self.buf[self.got..self.got + n].copy_from_slice(&data[..n]);
            }
            self.got += n;
            data = &data[n..];
            if self.got == self.need {
                self.got = 0;
                self.advance();
            }
        }
    }
    fn next(&mut self, step: u8, need: usize, skip: bool) {
        self.step = step;
        self.need = need;
        self.skip = skip;
    }
    fn u16(&self) -> u16 {
        u16::from_be_bytes([self.buf[0], self.buf[1]])
    }
    /// Field complete: move to the next one (zero-length fields fall through).
    fn advance(&mut self) {
        loop {
            match self.step {
                0 => {
                    if self.buf[0] != 2 {
                        self.result = Hello::NotServer;
                        return;
                    }
                    self.msg_left = (usize::from(self.buf[1]) << 16)
                        | (usize::from(self.buf[2]) << 8)
                        | usize::from(self.buf[3]);
                    self.next(1, 2 + 32, true); // legacy_version, random
                }
                1 => self.next(2, 1, false), // legacy_session_id length
                2 => {
                    let n = usize::from(self.buf[0]);
                    self.next(3, n, true);
                }
                3 => self.next(4, 2, false), // cipher_suite
                4 => {
                    self.cipher = self.u16();
                    self.next(5, 1, true); // legacy_compression_method
                }
                5 => self.next(6, 2, false), // extensions length
                6 | 8 | 9 => {
                    if self.step == 6 {
                        self.ext_left = usize::from(self.u16());
                    } else if self.step == 8 {
                        self.version = self.u16();
                    }
                    if self.ext_left == 0 {
                        self.result = Hello::Server(
                            self.version == 0x0304 && matches!(self.cipher, 0x1301..=0x1304),
                        );
                        return;
                    }
                    if self.ext_left < 4 {
                        self.result = Hello::Server(false);
                        return;
                    }
                    self.ext_left -= 4;
                    self.next(7, 4, false);
                }
                7 => {
                    let kind = self.u16();
                    let len = usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]]));
                    if len > self.ext_left {
                        self.result = Hello::Server(false);
                        return;
                    }
                    self.ext_left -= len;
                    if kind == 43 {
                        // supported_versions in a ServerHello: selected_version.
                        if len != 2 {
                            self.result = Hello::Server(false);
                            return;
                        }
                        self.next(8, 2, false);
                    } else {
                        self.next(9, len, true);
                    }
                }
                _ => unreachable!(),
            }
            if self.need != 0 {
                return;
            }
        }
    }
}

#[derive(Default)]
pub struct TlsRecords {
    header: [u8; 5],
    used: usize,
    remaining: usize,
    kind: u8,
    known: bool,
    pub(crate) passthrough: bool,
    failed: bool,
    check_hello: bool,
    hello: [u8; 6],
    hello_used: usize,
    scan: HelloScan,
}
impl TlsRecords {
    pub(crate) fn failed(&self) -> bool {
        self.failed
    }
    pub fn hello(&self) -> Hello {
        self.scan.result
    }
    /// Classify a chunk on its own (TLS 1.3 must be confirmed by a ServerHello
    /// in this same stream).
    pub fn encrypted_chunk(&mut self, data: &[u8]) -> bool {
        let mut tls13 = match self.scan.result {
            Hello::Server(v) => Some(v),
            _ => None,
        };
        self.classify(data, &mut tls13).0
    }
    /// Returns whether the whole chunk may pass through, and where its inner
    /// record headers lie. `tls13` is the session's ServerHello verdict, shared
    /// with the opposite direction; a ServerHello in this stream sets it.
    pub fn classify(&mut self, data: &[u8], tls13: &mut Option<bool>) -> (bool, Layout) {
        let mut layout = Layout::default();
        if !self.passthrough && *tls13 == Some(false) {
            self.failed = true;
        }
        if self.failed || data.is_empty() {
            return (false, layout);
        }
        if self.remaining == 0 && self.used != 0 {
            layout.cont = (5 - self.used).min(data.len()) as u8;
        }
        let mut all = true;
        let mut pos = 0;
        while pos < data.len() {
            if self.remaining == 0 {
                if self.used == 0 && layout.skip.is_none() {
                    layout.skip = Some(pos as u32);
                }
                let n = (5 - self.used).min(data.len() - pos);
                self.header[self.used..self.used + n].copy_from_slice(&data[pos..pos + n]);
                self.used += n;
                pos += n;
                // A partial header before the latch is intentionally FULL.
                if self.used != 5 {
                    all &= self.passthrough;
                    break;
                }
                self.used = 0;
                let kind = self.header[0];
                let len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if self.passthrough {
                    if kind != 23
                        || self.header[1..3] != [3, 3]
                        || !(MIN_CIPHERTEXT..=MAX_CIPHERTEXT).contains(&len)
                    {
                        return self.fail();
                    }
                } else {
                    if !(20..=23).contains(&kind)
                        || self.header[1] != 3
                        || !(1..=3).contains(&self.header[2])
                        || len == 0
                        || len > 18432
                    {
                        return self.fail();
                    }
                    if !self.known {
                        if kind != 22 || len < 38 {
                            return self.fail();
                        }
                        self.check_hello = true;
                    }
                    // ClientHello/ServerHello/CCS/alerts always remain FULL. TLS 1.3 encrypted
                    // handshake/application records have type 23 and may bypass outer payload AEAD.
                    if kind == 23 && (len < MIN_CIPHERTEXT || self.header[2] != 3) {
                        return self.fail();
                    }
                    if self.known && kind == 23 && *tls13 == Some(true) {
                        // Latched. Earlier handshake bytes in this chunk keep THIS command FULL.
                        self.passthrough = true;
                    } else {
                        // Before a TLS 1.3 verdict (e.g. 0-RTT data): FULL, keep tracking.
                        all = false;
                    }
                }
                self.kind = kind;
                self.remaining = len;
            }
            let n = self.remaining.min(data.len() - pos);
            let body = &data[pos..pos + n];
            if self.check_hello {
                let copy = (6 - self.hello_used).min(n);
                self.hello[self.hello_used..self.hello_used + copy].copy_from_slice(&body[..copy]);
                self.hello_used += copy;
                if self.hello_used == 6 {
                    let length = (usize::from(self.hello[1]) << 16)
                        | (usize::from(self.hello[2]) << 8)
                        | usize::from(self.hello[3]);
                    if !matches!(self.hello[0], 1 | 2) || length < 34 || self.hello[4..] != [3, 3] {
                        return self.fail();
                    }
                    self.known = true;
                    self.check_hello = false;
                }
            }
            if !self.passthrough && self.kind == 22 && self.scan.result == Hello::Pending {
                self.scan.feed(body);
                if let Hello::Server(v) = self.scan.result {
                    if tls13.is_none() {
                        *tls13 = Some(v);
                    }
                    if !v {
                        return self.fail();
                    }
                }
            }
            all &= self.passthrough;
            pos += n;
            self.remaining -= n;
        }
        let pass = all && self.passthrough;
        (pass, if pass { layout } else { Layout::default() })
    }
    fn fail(&mut self) -> (bool, Layout) {
        self.failed = true;
        (false, Layout::default())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    /// ServerHello record selecting TLS 1.3 / `cipher` via supported_versions.
    pub(crate) fn server_hello_with(version: u16, cipher: u16) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0x11; 32]);
        body.push(32);
        body.extend([0x22; 32]); // legacy_session_id echo
        body.extend(cipher.to_be_bytes());
        body.push(0);
        let mut ext = vec![0, 51, 0, 36, 0, 29, 0, 32]; // key_share x25519
        ext.extend([0x33; 32]);
        ext.extend([0, 43, 0, 2]);
        ext.extend(version.to_be_bytes());
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(ext);
        let mut hs = vec![2, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend(body);
        let mut rec = vec![22, 3, 3, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend(hs);
        rec
    }
    pub(crate) fn server_hello() -> Vec<u8> {
        server_hello_with(0x0304, 0x1301)
    }
    pub(crate) fn client_hello() -> Vec<u8> {
        let mut v = vec![22, 3, 3, 0, 38, 1, 0, 0, 34, 3, 3];
        v.extend([0; 32]);
        v
    }
    #[test]
    fn hello_plaintext_and_boundaries() {
        let hello = server_hello();
        let mut encrypted = vec![23, 3, 3, 0, 20];
        encrypted.extend([9; 20]);
        let mut c = TlsRecords::default();
        assert!(!c.encrypted_chunk(&hello));
        assert_eq!(c.hello(), Hello::Server(true));
        assert!(c.encrypted_chunk(&encrypted));
        assert!(c.encrypted_chunk(&encrypted));
        for split in 0..hello.len() {
            let mut c = TlsRecords::default();
            assert!(!c.encrypted_chunk(&hello[..split]));
            assert!(!c.encrypted_chunk(&hello[split..]));
            assert_eq!(c.hello(), Hello::Server(true), "split {split}");
            assert!(c.encrypted_chunk(&encrypted));
        }
        let mut c = TlsRecords::default();
        let mut mixed = hello.to_vec();
        mixed.extend_from_slice(&encrypted);
        assert!(!c.encrypted_chunk(&mixed));
        assert!(c.encrypted_chunk(&encrypted));
        for split in 1..encrypted.len() {
            let mut c = TlsRecords::default();
            assert!(!c.encrypted_chunk(&hello));
            let first = c.encrypted_chunk(&encrypted[..split]);
            assert_eq!(first, split >= 5);
            assert!(c.encrypted_chunk(&encrypted[split..]));
        }
        let mut c = TlsRecords::default();
        assert!(!c.encrypted_chunk(&encrypted));
        // After the latch record headers are followed, bodies are skipped.
        let mut c2 = TlsRecords::default();
        assert!(!c2.encrypted_chunk(&hello));
        let mut t = Some(true);
        assert_eq!(c2.classify(&encrypted[..7], &mut t), (true, Layout { cont: 0, skip: Some(0) }));
        assert_eq!(c2.classify(&encrypted[7..], &mut t), (true, Layout::default()));
        assert_eq!(c2.classify(&encrypted[..3], &mut t), (true, Layout { cont: 0, skip: Some(0) }));
        assert_eq!(c2.classify(&encrypted[3..], &mut t), (true, Layout { cont: 2, skip: None }));
        assert_eq!(c2.classify(&encrypted[..5], &mut t), (true, Layout { cont: 0, skip: Some(0) }));
        let mut body = encrypted[5..].to_vec();
        body.extend_from_slice(&encrypted);
        assert_eq!(c2.classify(&body, &mut t), (true, Layout { cont: 0, skip: Some(20) }));
        assert_eq!(c2.classify(b"not a TLS record header", &mut t), (false, Layout::default()));
        assert!(c2.failed());
    }
    #[test]
    fn tls13_verdict_required_and_strict_after_latch() {
        let mut encrypted = vec![23, 3, 3, 0, 20];
        encrypted.extend([9; 20]);
        // ClientHello alone: type 23 (0-RTT) stays FULL until the verdict arrives.
        let mut c = TlsRecords::default();
        let mut t = None;
        assert_eq!(c.classify(&client_hello(), &mut t).0, false);
        assert_eq!(c.hello(), Hello::NotServer);
        assert_eq!(c.classify(&encrypted, &mut t).0, false);
        assert!(!c.failed());
        t = Some(true); // ServerHello seen in the other direction
        assert_eq!(c.classify(&encrypted, &mut t).0, true);
        // TLS 1.2 or a non-TLS 1.3 suite: never passthrough.
        for (v, s) in [(0x0303, 0x1301), (0x0304, 0xc02f), (0x0304, 0x1305)] {
            let mut c = TlsRecords::default();
            let mut t = None;
            assert!(!c.classify(&server_hello_with(v, s), &mut t).0);
            assert_eq!(t, Some(false));
            assert!(c.failed());
            assert!(!c.classify(&encrypted, &mut t).0);
        }
        // TLS 1.2 ServerHello without supported_versions.
        let mut legacy = server_hello();
        let n = legacy.len();
        legacy.truncate(n - 6);
        let ext_at = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 1;
        let ext_len = u16::from_be_bytes([legacy[ext_at], legacy[ext_at + 1]]) - 6;
        legacy[ext_at..ext_at + 2].copy_from_slice(&ext_len.to_be_bytes());
        let fix = |v: &mut Vec<u8>, at: usize, d: usize| {
            let x = (usize::from(v[at]) << 8 | usize::from(v[at + 1])) - d;
            v[at] = (x >> 8) as u8;
            v[at + 1] = x as u8;
        };
        fix(&mut legacy, 3, 6);
        fix(&mut legacy, 7, 6);
        let mut c = TlsRecords::default();
        let mut t = None;
        assert!(!c.classify(&legacy, &mut t).0);
        assert_eq!(t, Some(false));
        // After the latch: alerts/handshake types, wrong version or bad lengths fail.
        for bad in [
            vec![21, 3, 3, 0, 20],
            vec![22, 3, 3, 0, 20],
            vec![23, 3, 1, 0, 20],
            vec![23, 3, 3, 0, 16],
            vec![23, 3, 3, 0x41, 0x01],
        ] {
            let mut c = TlsRecords::default();
            let mut t = None;
            c.classify(&server_hello(), &mut t);
            assert!(c.classify(&encrypted, &mut t).0);
            assert!(!c.classify(&bad, &mut t).0, "{bad:?}");
            assert!(c.failed());
        }
    }
}
