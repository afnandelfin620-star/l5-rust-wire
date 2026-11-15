//! Conservative streaming TLS record recognizer. No timers, no payload buffers.
//! It is NOT a TLS terminator: only record framing and initial hello are inspected.
//! Passthrough latches at the first recognized encrypted record. A chunk
//! containing earlier handshake bytes remains FULL at the transition. After the
//! latch the 5-byte record headers are still followed (record bodies are
//! skipped, never scanned) so their positions can be masked on the wire.
use crate::Layout;
#[derive(Default)]
pub struct TlsRecords {
    header: [u8; 5],
    used: usize,
    remaining: usize,
    known: bool,
    pub(crate) passthrough: bool,
    failed: bool,
    check_hello: bool,
    hello: [u8; 6],
    hello_used: usize,
}
impl TlsRecords {
    pub(crate) fn failed(&self) -> bool {
        self.failed
    }
    pub fn encrypted_chunk(&mut self, data: &[u8]) -> bool {
        self.classify(data).0
    }
    /// Returns whether the whole chunk may pass through, and where its inner
    /// record headers lie. A framing violation after the latch fails the
    /// session: the chunk and all later ones use FULL protection.
    pub fn classify(&mut self, data: &[u8]) -> (bool, Layout) {
        let mut layout = Layout::default();
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
                if !(20..=23).contains(&kind)
                    || self.header[1] != 3
                    || !(1..=3).contains(&self.header[2])
                    || len == 0
                    || len > 18432
                {
                    self.failed = true;
                    return (false, Layout::default());
                }
                if !self.passthrough {
                    if !self.known {
                        if kind != 22 || len < 38 {
                            self.failed = true;
                            return (false, Layout::default());
                        }
                        self.check_hello = true;
                    }
                    // ClientHello/ServerHello/CCS/alerts always remain FULL. TLS 1.3 encrypted
                    // handshake/application records have type 23 and may bypass outer payload AEAD.
                    if kind == 23 && (len < 17 || self.header[2] != 3) {
                        self.failed = true;
                        return (false, Layout::default());
                    }
                    if self.known && kind == 23 {
                        // Latched. Earlier handshake bytes in this chunk keep THIS command FULL.
                        self.passthrough = true;
                    } else {
                        all = false;
                    }
                }
                self.remaining = len;
            }
            let n = self.remaining.min(data.len() - pos);
            if self.check_hello {
                let copy = (6 - self.hello_used).min(n);
                self.hello[self.hello_used..self.hello_used + copy].copy_from_slice(&data[pos..pos + copy]);
                self.hello_used += copy;
                if self.hello_used == 6 {
                    let length = (usize::from(self.hello[1]) << 16)
                        | (usize::from(self.hello[2]) << 8)
                        | usize::from(self.hello[3]);
                    if !matches!(self.hello[0], 1 | 2) || length < 34 || self.hello[4..] != [3, 3] {
                        self.failed = true;
                        return (false, Layout::default());
                    }
                    self.known = true;
                    self.check_hello = false;
                }
            }
            all &= self.passthrough;
            pos += n;
            self.remaining -= n;
        }
        let pass = all && self.passthrough;
        (pass, if pass { layout } else { Layout::default() })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hello_plaintext_and_boundaries() {
        let mut hello = vec![22, 3, 3, 0, 38, 1, 0, 0, 34, 3, 3];
        hello.extend([0; 32]);
        let mut encrypted = vec![23, 3, 3, 0, 20];
        encrypted.extend([9; 20]);
        let mut c = TlsRecords::default();
        assert!(!c.encrypted_chunk(&hello));
        assert!(c.encrypted_chunk(&encrypted));
        // After the latch record headers are followed, bodies are skipped.
        assert_eq!(c.classify(&encrypted), (true, Layout { cont: 0, skip: Some(0) }));
        let mut c2 = TlsRecords::default();
        assert!(!c2.encrypted_chunk(&hello));
        assert_eq!(c2.classify(&encrypted[..7]), (true, Layout { cont: 0, skip: Some(0) }));
        assert_eq!(c2.classify(&encrypted[7..]), (true, Layout::default()));
        assert_eq!(c2.classify(&encrypted[..3]), (true, Layout { cont: 0, skip: Some(0) }));
        assert_eq!(c2.classify(&encrypted[3..]), (true, Layout { cont: 2, skip: None }));
        assert_eq!(c2.classify(&encrypted[..5]), (true, Layout { cont: 0, skip: Some(0) }));
        let mut body = encrypted[5..].to_vec();
        body.extend_from_slice(&encrypted);
        assert_eq!(c2.classify(&body), (true, Layout { cont: 0, skip: Some(20) }));
        assert_eq!(c2.classify(b"not a TLS record header"), (false, Layout::default()));
        assert!(c2.failed());
        assert!(c.encrypted_chunk(&encrypted));
        for split in 0..hello.len() {
            let mut c = TlsRecords::default();
            assert!(!c.encrypted_chunk(&hello[..split]));
            assert!(!c.encrypted_chunk(&hello[split..]));
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
            if split < 5 {
                assert!(!first);
            } else {
                assert!(first);
            }
            assert!(c.encrypted_chunk(&encrypted[split..]));
        }
        let mut c = TlsRecords::default();
        assert!(!c.encrypted_chunk(&encrypted));
    }
}
