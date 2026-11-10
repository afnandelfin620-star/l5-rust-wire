//! Conservative streaming TLS record recognizer. No timers, no payload buffers.
//! It is NOT a TLS terminator: only record framing and initial hello are inspected.
//! The entire command payload remains FULL if any byte is not known encrypted.
#[derive(Default)]
pub struct TlsRecords {
    header: [u8; 5],
    used: usize,
    remaining: usize,
    known: bool,
    failed: bool,
    encrypted: bool,
    check_hello: bool,
    hello: [u8; 6],
    hello_used: usize,
}
impl TlsRecords {
    pub fn encrypted_chunk(&mut self, mut data: &[u8]) -> bool {
        if self.failed || data.is_empty() {
            return false;
        }
        let mut all = true;
        while !data.is_empty() {
            if self.remaining == 0 {
                let needed = 5 - self.used;
                let n = needed.min(data.len());
                self.header[self.used..self.used + n].copy_from_slice(&data[..n]);
                self.used += n;
                data = &data[n..];
                // A partial header is intentionally FULL. Continuation will be validated later.
                if self.used != 5 {
                    return false;
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
                    return false;
                }
                if !self.known {
                    if kind != 22 || len < 38 {
                        self.failed = true;
                        return false;
                    }
                    self.check_hello = true;
                }
                // ClientHello/ServerHello/CCS/alerts always remain FULL. TLS 1.3 encrypted
                // handshake/application records have type 23 and may bypass outer payload AEAD (header remains authenticated).
                if kind == 23 && (len < 17 || self.header[2] != 3) {
                    self.failed = true;
                    return false;
                }
                self.encrypted = self.known && kind == 23;
                all &= self.encrypted;
                self.remaining = len;
            }
            let n = self.remaining.min(data.len());
            if n == 0 {
                break;
            }
            if self.check_hello {
                let copy = (6 - self.hello_used).min(n);
                self.hello[self.hello_used..self.hello_used + copy].copy_from_slice(&data[..copy]);
                self.hello_used += copy;
                if self.hello_used == 6 {
                    let length = (usize::from(self.hello[1]) << 16)
                        | (usize::from(self.hello[2]) << 8)
                        | usize::from(self.hello[3]);
                    if !matches!(self.hello[0], 1 | 2) || length < 34 || self.hello[4..] != [3, 3] {
                        self.failed = true;
                        return false;
                    }
                    self.known = true;
                    self.check_hello = false;
                }
            }
            all &= self.encrypted;
            data = &data[n..];
            self.remaining -= n;
        }
        all
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
        assert!(!c.encrypted_chunk(b"GET / HTTP/1.1"));
        assert!(!c.encrypted_chunk(&encrypted));
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
