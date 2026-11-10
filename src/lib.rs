#[cfg(feature = "size-diagnostics")]
pub mod diagnostics;
use anyhow::{ensure, Result};
use bytes::{Bytes, BytesMut};
use ring::{aead, hkdf};
use std::{
    io::IoSlice,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub mod sniff;
pub mod transport;
pub const MODE: &str = "l5-android-v2";
pub const HELLO: u8 = 1;
pub const ECHO: u8 = 2;
pub const OPEN: u8 = 3;
pub const DATA: u8 = 4;
pub const FIN: u8 = 5;
pub const CLOSE: u8 = 6;
pub const L5: u8 = 7;
pub const PING: u8 = 8;
pub const PONG: u8 = 9;
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
const HEADER: usize = 20;
const TAG: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Protection {
    Full = 0,
    TlsPassthrough = 1,
}
pub struct Message {
    pub cmd: u8,
    pub id: u32,
    pub protection: Protection,
    pub payload: Bytes,
}
struct Keys {
    header: aead::LessSafeKey,
    full: aead::LessSafeKey,
}
struct KeyLen;
impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        16
    }
}
fn key(root: &[u8], label: &[u8]) -> Result<aead::LessSafeKey> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"L5-WIRE-v2").extract(root);
    let mut bytes = [0u8; 16];
    prk.expand(&[label], KeyLen)
        .map_err(|_| anyhow::anyhow!("HKDF expand"))?
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("HKDF fill"))?;
    let result = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &bytes)
            .map_err(|_| anyhow::anyhow!("AEAD key"))?,
    );
    bytes.fill(0);
    Ok(result)
}
fn keys(root: &[u8], direction: &str) -> Result<Keys> {
    Ok(Keys {
        header: key(root, format!("{direction}/header").as_bytes())?,
        full: key(root, format!("{direction}/full").as_bytes())?,
    })
}
fn nonce(seq: u64) -> aead::Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    aead::Nonce::assume_unique_for_key(n)
}
pub struct Encoder {
    keys: Keys,
    seq: u64,
}
pub struct Decoder {
    keys: Keys,
    seq: u64,
    header: [u8; HEADER + TAG],
    used: usize,
    meta: Option<Meta>,
    payload: BytesMut,
    failed: bool,
    pub legacy_data: bool,
    chunk: Bytes,
    streamed: usize,
}
#[derive(Clone, Copy)]
struct Meta {
    cmd: u8,
    id: u32,
    mode: Protection,
    len: usize,
    headroom: usize,
}
pub struct Encoded {
    header: [u8; HEADER + TAG],
    pub payload: Bytes,
    tag: [u8; TAG],
    tag_len: usize,
    offset: usize,
}
impl Encoded {
    pub fn poll_write<S: AsyncWrite + Unpin>(
        &mut self,
        s: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        let total = self.header.len() + self.payload.len() + self.tag_len;
        while self.offset < total {
            let chunks = [
                &self.header[..],
                &self.payload[..],
                &self.tag[..self.tag_len],
            ];
            let mut skip = self.offset;
            let mut slices = [IoSlice::new(&[]), IoSlice::new(&[]), IoSlice::new(&[])];
            let mut count = 0;
            for part in chunks {
                if skip >= part.len() {
                    skip -= part.len();
                } else {
                    slices[count] = IoSlice::new(&part[skip..]);
                    skip = 0;
                    count += 1;
                }
            }
            let n = ready!(Pin::new(&mut *s).poll_write_vectored(cx, &slices[..count]))?;
            if n == 0 {
                return Poll::Ready(Err(anyhow::anyhow!("zero write")));
            }
            self.offset += n;
        }
        Poll::Ready(Ok(()))
    }
    pub async fn write<S: AsyncWrite + Unpin>(&mut self, s: &mut S) -> Result<()> {
        futures::future::poll_fn(|cx| self.poll_write(s, cx)).await
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = self.header.to_vec();
        v.extend_from_slice(&self.payload);
        v.extend_from_slice(&self.tag[..self.tag_len]);
        v
    }
}
pub fn codecs(root: &[u8], client: bool) -> Result<(Decoder, Encoder)> {
    let (recv, send) = if client {
        ("server", "client")
    } else {
        ("client", "server")
    };
    Ok((
        Decoder {
            keys: keys(root, recv)?,
            seq: 0,
            header: [0; HEADER + TAG],
            used: 0,
            meta: None,
            payload: BytesMut::new(),
            failed: false,
            legacy_data: false,
            chunk: Bytes::new(),
            streamed: 0,
        },
        Encoder {
            keys: keys(root, send)?,
            seq: 0,
        },
    ))
}
impl Encoder {
    pub fn prepare(
        &mut self,
        cmd: u8,
        id: u32,
        mode: Protection,
        payload: Bytes,
    ) -> Result<Encoded> {
        ensure!(payload.len() <= MAX_PAYLOAD, "frame too large");
        ensure!(self.seq < u64::MAX, "sequence exhausted");
        ensure!(
            matches!(cmd, ECHO | DATA) || mode == Protection::Full,
            "control must use full protection"
        );
        let mut header = [0u8; HEADER + TAG];
        header[0] = 2;
        header[1] = cmd;
        header[2] = mode as u8;
        header[4..8].copy_from_slice(&id.to_be_bytes());
        header[8..16].copy_from_slice(&self.seq.to_be_bytes());
        header[16..20].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let (payload, tag) = match mode {
            Protection::Full => {
                // Unique owned Bytes is encrypted in place; immutable pbuf-backed Bytes needs
                // one copy only when full protection is required. No concatenation buffer.
                let mut buf = payload
                    .try_into_mut()
                    .unwrap_or_else(|b| BytesMut::from(b.as_ref()));
                let tag = self
                    .keys
                    .full
                    .seal_in_place_separate_tag(
                        nonce(self.seq),
                        aead::Aad::from(&header[..HEADER]),
                        &mut buf,
                    )
                    .map_err(|_| anyhow::anyhow!("payload seal"))?;
                (buf.freeze(), Some(tag))
            }
            // The inner application TLS protects its ciphertext. Deliberately no outer
            // payload encryption, MAC/GHASH, or payload scan in this branch.
            Protection::TlsPassthrough => (payload, None),
        };
        let htag = self
            .keys
            .header
            .seal_in_place_separate_tag(nonce(self.seq), aead::Aad::empty(), &mut header[..HEADER])
            .map_err(|_| anyhow::anyhow!("header seal"))?;
        header[HEADER..].copy_from_slice(htag.as_ref());
        let mut tail = [0; TAG];
        let tag_len = if let Some(tag) = tag {
            tail.copy_from_slice(tag.as_ref());
            TAG
        } else {
            0
        };
        self.seq += 1;
        Ok(Encoded {
            header,
            payload,
            tag: tail,
            tag_len,
            offset: 0,
        })
    }
    pub fn encode(
        &mut self,
        cmd: u8,
        id: u32,
        mode: Protection,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        Ok(self
            .prepare(cmd, id, mode, Bytes::copy_from_slice(payload))?
            .to_vec())
    }
    pub async fn write<S: AsyncWrite + Unpin>(
        &mut self,
        s: &mut S,
        cmd: u8,
        id: u32,
        mode: Protection,
        payload: &[u8],
    ) -> Result<()> {
        let mut frame = self.prepare(cmd, id, mode, Bytes::copy_from_slice(payload))?;
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            frame.write(s).await?;
            s.flush().await?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }
}
impl Decoder {
    pub(crate) fn frame_complete(&self) -> bool {
        self.meta.is_none()
    }
    /// Owned receive path: keep TLS slab ownership through L5 parsing. Only the
    /// 36-byte authenticated header is gathered. Passthrough DATA is delivered as
    /// slices (possibly several for one wire frame); full AEAD waits for its tag.
    pub async fn read_owned<S>(
        &mut self,
        s: &mut S,
        read: fn(&mut S, &mut Context<'_>) -> Poll<std::io::Result<Bytes>>,
    ) -> Result<Message> {
        ensure!(!self.failed, "decoder failed");
        let result = self.read_owned_inner(s, read).await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    async fn read_owned_inner<S>(
        &mut self,
        s: &mut S,
        read: fn(&mut S, &mut Context<'_>) -> Poll<std::io::Result<Bytes>>,
    ) -> Result<Message> {
        ensure!(self.seq < u64::MAX, "sequence exhausted");
        if self.meta.is_none() {
            while self.used < self.header.len() {
                self.refill(s, read).await?;
                let n = (self.header.len() - self.used).min(self.chunk.len());
                self.header[self.used..self.used + n].copy_from_slice(&self.chunk.split_to(n));
                self.used += n;
            }
            let h = self
                .keys
                .header
                .open_in_place(nonce(self.seq), aead::Aad::empty(), &mut self.header)
                .map_err(|_| anyhow::anyhow!("header authentication failed"))?;
            ensure!(h[0] == 2 && h[3] == 0, "frame version/reserved");
            ensure!(
                u64::from_be_bytes(h[8..16].try_into()?) == self.seq,
                "sequence mismatch"
            );
            let mode = match h[2] {
                0 => Protection::Full,
                1 => Protection::TlsPassthrough,
                _ => anyhow::bail!("unknown mode"),
            };
            let cmd = h[1];
            ensure!((HELLO..=PONG).contains(&cmd), "unknown command");
            ensure!(
                matches!(cmd, ECHO | DATA) || mode == Protection::Full,
                "control protection"
            );
            let len = u32::from_be_bytes(h[16..20].try_into()?) as usize;
            ensure!(len <= MAX_PAYLOAD, "oversized frame");
            let id = u32::from_be_bytes(h[4..8].try_into()?);
            let headroom = if self.legacy_data && cmd == DATA && mode == Protection::Full {
                5
            } else {
                0
            };
            self.meta = Some(Meta {
                cmd,
                id,
                mode,
                len,
                headroom,
            });
            self.streamed = 0;
            if mode == Protection::Full || cmd != DATA {
                self.payload.reserve(headroom + len + TAG);
                self.payload.resize(headroom, 0);
            }
        }
        let m = self.meta.unwrap();
        if m.mode == Protection::TlsPassthrough && m.cmd == DATA {
            let left = m.len - self.streamed;
            if left > 0 {
                self.refill(s, read).await?;
            }
            let payload = self.chunk.split_to(left.min(self.chunk.len()));
            self.streamed += payload.len();
            if self.streamed == m.len {
                self.finish_owned();
            }
            return Ok(Message {
                cmd: m.cmd,
                id: m.id,
                protection: m.mode,
                payload,
            });
        }
        let total = m.headroom + m.len + if m.mode == Protection::Full { TAG } else { 0 };
        while self.payload.len() < total {
            self.refill(s, read).await?;
            let n = (total - self.payload.len()).min(self.chunk.len());
            self.payload.extend_from_slice(&self.chunk.split_to(n));
        }
        if m.mode == Protection::Full {
            self.keys
                .full
                .open_in_place(
                    nonce(self.seq),
                    aead::Aad::from(&self.header[..HEADER]),
                    &mut self.payload[m.headroom..],
                )
                .map_err(|_| anyhow::anyhow!("payload authentication failed"))?;
        }
        self.payload.truncate(m.headroom + m.len);
        if m.headroom != 0 {
            self.payload[0] = 1;
            self.payload[1..3].copy_from_slice(&(m.id as u16).to_le_bytes());
            self.payload[3..5].copy_from_slice(&((m.id >> 16) as u16).to_le_bytes());
        }
        let payload = std::mem::take(&mut self.payload).freeze();
        self.finish_owned();
        Ok(Message {
            cmd: m.cmd,
            id: m.id,
            protection: m.mode,
            payload,
        })
    }
    async fn refill<S>(
        &mut self,
        s: &mut S,
        read: fn(&mut S, &mut Context<'_>) -> Poll<std::io::Result<Bytes>>,
    ) -> Result<()> {
        if self.chunk.is_empty() {
            self.chunk = futures::future::poll_fn(|cx| read(s, cx)).await?;
            ensure!(!self.chunk.is_empty(), "frame EOF");
        }
        Ok(())
    }
    fn finish_owned(&mut self) {
        #[cfg(feature = "size-diagnostics")]
        if let Some(m) = self.meta {
            let kind = if m.cmd == DATA {
                if m.mode == Protection::Full {
                    0
                } else {
                    1
                }
            } else {
                2
            };
            diagnostics::record(kind, m.len);
        }
        self.meta = None;
        self.used = 0;
        self.seq += 1;
        self.streamed = 0;
    }
    pub async fn read<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Result<Message> {
        ensure!(!self.failed, "decoder failed");
        let r = self.read_inner(s).await;
        if r.is_err() {
            self.failed = true;
        }
        r
    }
    async fn read_inner<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Result<Message> {
        ensure!(self.seq < u64::MAX, "sequence exhausted");
        if self.meta.is_none() {
            while self.used < self.header.len() {
                let n = s.read(&mut self.header[self.used..]).await?;
                ensure!(n != 0, "frame EOF");
                self.used += n;
            }
            let h = self
                .keys
                .header
                .open_in_place(nonce(self.seq), aead::Aad::empty(), &mut self.header)
                .map_err(|_| anyhow::anyhow!("header authentication failed"))?;
            ensure!(h[0] == 2 && h[3] == 0, "frame version/reserved");
            ensure!(
                u64::from_be_bytes(h[8..16].try_into()?) == self.seq,
                "sequence mismatch"
            );
            let mode = match h[2] {
                0 => Protection::Full,
                1 => Protection::TlsPassthrough,
                _ => anyhow::bail!("unknown mode"),
            };
            let cmd = h[1];
            ensure!((HELLO..=PONG).contains(&cmd), "unknown command");
            ensure!(
                matches!(cmd, ECHO | DATA) || mode == Protection::Full,
                "control protection"
            );
            let len = u32::from_be_bytes(h[16..20].try_into()?) as usize;
            ensure!(len <= MAX_PAYLOAD, "oversized frame");
            let id = u32::from_be_bytes(h[4..8].try_into()?);
            let headroom = if self.legacy_data && cmd == DATA {
                5
            } else {
                0
            };
            self.payload.reserve(headroom + len + TAG);
            self.payload.resize(headroom, 0);
            self.meta = Some(Meta {
                cmd,
                id,
                mode,
                len,
                headroom,
            });
        }
        let m = self.meta.unwrap();
        let total = m.headroom + m.len + if m.mode == Protection::Full { TAG } else { 0 };
        while self.payload.len() < total {
            let missing = total - self.payload.len();
            let n = (&mut *s)
                .take(missing as u64)
                .read_buf(&mut self.payload)
                .await?;
            ensure!(n > 0, "payload EOF");
        }
        match m.mode {
            Protection::Full => {
                self.keys
                    .full
                    .open_in_place(
                        nonce(self.seq),
                        aead::Aad::from(&self.header[..HEADER]),
                        &mut self.payload[m.headroom..],
                    )
                    .map_err(|_| anyhow::anyhow!("payload authentication failed"))?;
            }
            Protection::TlsPassthrough => {}
        }
        self.payload.truncate(m.headroom + m.len);
        if m.headroom != 0 {
            self.payload[0] = 1;
            self.payload[1..3].copy_from_slice(&(m.id as u16).to_le_bytes());
            self.payload[3..5].copy_from_slice(&((m.id >> 16) as u16).to_le_bytes());
        }
        let payload = std::mem::take(&mut self.payload).freeze();
        self.meta = None;
        self.used = 0;
        self.seq += 1;
        Ok(Message {
            cmd: m.cmd,
            id: m.id,
            protection: m.mode,
            payload,
        })
    }
}
