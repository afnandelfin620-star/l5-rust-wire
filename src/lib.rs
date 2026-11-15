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
pub mod fixed;
pub mod sniff;
pub mod transport;
pub const MODE: &str = "l5-android-v3";
pub const HELLO: u8 = 1;
pub const ECHO: u8 = 2;
pub const OPEN: u8 = 3;
pub const DATA: u8 = 4;
pub const FIN: u8 = 5;
pub const CLOSE: u8 = 6;
pub const L5: u8 = 7;
pub const PING: u8 = 8;
pub const PONG: u8 = 9;
/// Maximum payload of one L5 command; IO capacity is not message capacity.
pub const MAX_PAYLOAD: usize = 256 * 1024;
/// Authenticated header: version, cmd, mode, layout.cont, id, seq, len, layout.skip.
const HEADER: usize = 24;
const TAG: usize = 16;
const NO_SKIP: u32 = u32::MAX;
/// Masked inner TLS record headers kept beside a borrowed payload. More
/// headers than this in one frame use an owned/scratch payload instead.
const INLINE_MASKS: usize = 16;

/// Where the inner TLS record headers of one passthrough payload lie. The
/// receiver needs no per-session state: `cont` leading bytes finish a header
/// begun in an earlier frame, and a header chain starts at `skip`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    pub cont: u8,
    pub skip: Option<u32>,
}
impl Layout {
    pub fn is_empty(&self) -> bool {
        self.cont == 0 && self.skip.is_none()
    }
}
/// Visit header pieces `(offset, count)` of an `n`-byte payload. `f` returns
/// the record length of a complete (count == 5) header after it is readable.
pub(crate) fn walk_headers(layout: Layout, n: usize, mut f: impl FnMut(usize, usize) -> usize) {
    let cont = usize::from(layout.cont).min(n);
    if cont != 0 {
        f(0, cont);
    }
    let Some(skip) = layout.skip else { return };
    let mut p = skip as usize;
    while p < n {
        let c = (n - p).min(5);
        let len = f(p, c);
        if c < 5 {
            break;
        }
        p = p.saturating_add(5 + len);
    }
}
fn record_len(h: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([h[3], h[4]]))
}
fn header_mask(key: &aead::quic::HeaderProtectionKey, seq: u64, offset: usize) -> Result<[u8; 5]> {
    let mut sample = [0u8; 16];
    sample[..8].copy_from_slice(&seq.to_be_bytes());
    sample[8..12].copy_from_slice(&(offset as u32).to_be_bytes());
    key.new_mask(&sample).map_err(|_| anyhow::anyhow!("header mask"))
}
/// Unmask inner TLS record headers in a contiguous received payload.
pub(crate) fn unmask(key: &aead::quic::HeaderProtectionKey, seq: u64, layout: Layout, buf: &mut [u8]) -> Result<()> {
    let mut result = Ok(());
    walk_headers(layout, buf.len(), |p, c| {
        match header_mask(key, seq, p) {
            Ok(m) => buf[p..p + c].iter_mut().zip(m).for_each(|(b, m)| *b ^= m),
            Err(e) => result = Err(e),
        }
        if c == 5 { record_len(&buf[p..p + 5]) } else { 0 }
    });
    result
}
pub(crate) fn parse_layout(h: &[u8], mode: Protection, len: usize) -> Result<Layout> {
    let skip = u32::from_be_bytes(h[20..24].try_into()?);
    let layout = Layout { cont: h[3], skip: (skip != NO_SKIP).then_some(skip) };
    if mode == Protection::Full {
        ensure!(layout.is_empty(), "layout on full frame");
    } else {
        let cont = usize::from(layout.cont);
        ensure!(cont <= 4 && cont <= len, "invalid header continuation");
        ensure!(
            layout.skip.is_none_or(|s| (s as usize) >= cont && (s as usize) < len),
            "invalid header offset"
        );
    }
    Ok(layout)
}
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
    mask: aead::quic::HeaderProtectionKey,
}
struct KeyLen;
impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        16
    }
}
fn key_bytes(root: &[u8], label: &[u8]) -> Result<[u8; 16]> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"L5-WIRE-v2").extract(root);
    let mut bytes = [0u8; 16];
    prk.expand(&[label], KeyLen)
        .map_err(|_| anyhow::anyhow!("HKDF expand"))?
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("HKDF fill"))?;
    Ok(bytes)
}
fn key(root: &[u8], label: &[u8]) -> Result<aead::LessSafeKey> {
    let mut bytes = key_bytes(root, label)?;
    let result = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &bytes)
            .map_err(|_| anyhow::anyhow!("AEAD key"))?,
    );
    bytes.fill(0);
    Ok(result)
}
fn keys(root: &[u8], direction: &str) -> Result<Keys> {
    let mut mask = key_bytes(root, format!("{direction}/mask").as_bytes())?;
    let mask_key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &mask)
        .map_err(|_| anyhow::anyhow!("mask key"));
    mask.fill(0);
    Ok(Keys {
        header: key(root, format!("{direction}/header").as_bytes())?,
        full: key(root, format!("{direction}/full").as_bytes())?,
        mask: mask_key?,
    })
}
fn nonce(seq: u64) -> aead::Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    aead::Nonce::assume_unique_for_key(n)
}
pub struct Encoder {
    scratch: BytesMut,
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
    layout: Layout,
}
#[derive(Clone, Copy, Default)]
struct Mask {
    at: usize,
    len: usize,
    bytes: [u8; 5],
}
pub struct Encoded {
    header: [u8; HEADER + TAG],
    pub payload: Bytes,
    tag: [u8; TAG],
    tag_len: usize,
    offset: usize,
    /// Masked replacements for inner TLS record headers of a borrowed payload.
    masks: [Mask; INLINE_MASKS],
    mask_count: usize,
    /// Payload storage came from the encoder scratch and may be reclaimed.
    scratch: bool,
}
impl Encoded {
    pub(crate) fn written(&self) -> usize { self.offset }
    /// Logical frame parts: header, payload with masked header substitutions, tag.
    fn parts(&self) -> ([&[u8]; 2 * INLINE_MASKS + 3], usize) {
        let mut parts: [&[u8]; 2 * INLINE_MASKS + 3] = [&[]; 2 * INLINE_MASKS + 3];
        parts[0] = &self.header[..];
        let mut count = 1;
        let mut pos = 0;
        for m in &self.masks[..self.mask_count] {
            parts[count] = &self.payload[pos..m.at];
            parts[count + 1] = &m.bytes[..m.len];
            count += 2;
            pos = m.at + m.len;
        }
        parts[count] = &self.payload[pos..];
        parts[count + 1] = &self.tag[..self.tag_len];
        (parts, count + 2)
    }
    pub fn poll_write<S: AsyncWrite + Unpin>(
        &mut self,
        s: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        let total = self.header.len() + self.payload.len() + self.tag_len;
        while self.offset < total {
            let (chunks, parts) = self.parts();
            let mut skip = self.offset;
            let mut slices = [IoSlice::new(&[]); 2 * INLINE_MASKS + 3];
            let mut count = 0;
            for part in &chunks[..parts] {
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
        let (parts, count) = self.parts();
        parts[..count].concat()
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
            scratch: BytesMut::new(),            keys: keys(root, send)?,
            seq: 0,
        },
    ))
}
impl Encoder {
    pub(crate) fn reclaim(&mut self, frame: Encoded) {
        if frame.tag_len != 0 || frame.scratch {
            if let Ok(mut buf) = frame.payload.try_into_mut() {
                buf.clear();
                if buf.capacity() > self.scratch.capacity() { self.scratch = buf; }
            }
        }
    }

    pub fn prepare(
        &mut self,
        cmd: u8,
        id: u32,
        mode: Protection,
        payload: Bytes,
    ) -> Result<Encoded> {
        self.prepare_layout(cmd, id, mode, payload, Layout::default())
    }

    /// `layout` locates inner TLS record headers of a passthrough payload; they
    /// are masked so no plaintext TLS framing appears inside the outer record.
    pub fn prepare_layout(
        &mut self,
        cmd: u8,
        id: u32,
        mode: Protection,
        payload: Bytes,
        layout: Layout,
    ) -> Result<Encoded> {
        ensure!(payload.len() <= MAX_PAYLOAD, "frame too large");
        ensure!(self.seq < u64::MAX, "sequence exhausted");
        ensure!(
            matches!(cmd, ECHO | DATA) || mode == Protection::Full,
            "control must use full protection"
        );
        ensure!(
            mode == Protection::TlsPassthrough || layout.is_empty(),
            "layout requires passthrough"
        );
        ensure!(
            usize::from(layout.cont) <= 4
                && layout.skip.is_none_or(|s| (s as usize) < payload.len()),
            "invalid layout"
        );
        let mut header = [0u8; HEADER + TAG];
        header[0] = 2;
        header[1] = cmd;
        header[2] = mode as u8;
        header[3] = usize::from(layout.cont).min(payload.len()) as u8;
        header[4..8].copy_from_slice(&id.to_be_bytes());
        header[8..16].copy_from_slice(&self.seq.to_be_bytes());
        header[16..20].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        header[20..24].copy_from_slice(&layout.skip.unwrap_or(NO_SKIP).to_be_bytes());
        let layout = Layout { cont: header[3], skip: layout.skip };
        let mut masks = [Mask::default(); INLINE_MASKS];
        let mut mask_count = 0;
        let mut scratch = false;
        let (payload, tag) = match mode {
            Protection::Full =>
            {
                // Unique owned Bytes is encrypted in place; immutable pbuf-backed Bytes needs
                // one copy only when full protection is required. No concatenation buffer.
                let mut buf = match payload.try_into_mut() {
                    Ok(buf) => buf,
                    Err(b) => {
                        let mut buf = std::mem::take(&mut self.scratch);
                        buf.clear();
                        buf.extend_from_slice(&b);
                        buf
                    }
                };
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
            // payload encryption or MAC; only the 5-byte inner record headers are
            // masked (one AES block each), normally beside the borrowed payload.
            Protection::TlsPassthrough if layout.is_empty() => (payload, None),
            Protection::TlsPassthrough => {
                let seq = self.seq;
                let key = &self.keys.mask;
                let mut overflow = false;
                let mut failure = None;
                walk_headers(layout, payload.len(), |p, c| {
                    if mask_count == INLINE_MASKS {
                        overflow = true;
                    } else {
                        match header_mask(key, seq, p) {
                            Ok(m) => {
                                let slot = &mut masks[mask_count];
                                *slot = Mask { at: p, len: c, bytes: [0; 5] };
                                for i in 0..c {
                                    slot.bytes[i] = payload[p + i] ^ m[i];
                                }
                                mask_count += 1;
                            }
                            Err(e) => failure = Some(e),
                        }
                    }
                    if c == 5 { record_len(&payload[p..p + 5]) } else { 0 }
                });
                if let Some(e) = failure {
                    return Err(e);
                }
                if !overflow {
                    (payload, None)
                } else {
                    // Many tiny inner records: mask an owned buffer in place.
                    mask_count = 0;
                    scratch = true;
                    let mut buf = match payload.try_into_mut() {
                        Ok(buf) => buf,
                        Err(b) => {
                            let mut buf = std::mem::take(&mut self.scratch);
                            buf.clear();
                            buf.extend_from_slice(&b);
                            buf
                        }
                    };
                    let mut failure = None;
                    walk_headers(layout, buf.len(), |p, c| {
                        let len = if c == 5 { record_len(&buf[p..p + 5]) } else { 0 };
                        match header_mask(&self.keys.mask, seq, p) {
                            Ok(m) => buf[p..p + c].iter_mut().zip(m).for_each(|(b, m)| *b ^= m),
                            Err(e) => failure = Some(e),
                        }
                        len
                    });
                    if let Some(e) = failure {
                        return Err(e);
                    }
                    (buf.freeze(), None)
                }
            }
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
            masks,
            mask_count,
            scratch,
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
            ensure!(h[0] == 2, "frame version");
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
            let layout = parse_layout(h, mode, len)?;
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
                layout,
            });
            self.streamed = 0;
            // Masked passthrough cannot be fixed up in immutable slab slices; this
            // owned path (not used by the endpoints' fixed receivers) gathers it.
            if mode == Protection::Full || cmd != DATA || !layout.is_empty() {
                self.payload.reserve(headroom + len + TAG);
                self.payload.resize(headroom, 0);
            }
        }
        let m = self.meta.unwrap();
        if m.mode == Protection::TlsPassthrough && m.cmd == DATA && m.layout.is_empty() {
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
        } else {
            unmask(&self.keys.mask, self.seq, m.layout, &mut self.payload[m.headroom..])?;
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
            ensure!(h[0] == 2, "frame version");
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
            let layout = parse_layout(h, mode, len)?;
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
                layout,
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
            Protection::TlsPassthrough => unmask(&self.keys.mask, self.seq, m.layout, &mut self.payload[m.headroom..])?,
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

#[cfg(test)]
mod scratch_reuse_tests {
    use super::*;
    #[test]
    fn immutable_full_payload_reuses_encryption_storage() {
        let (_,mut encoder)=codecs(&[9;32],true).unwrap();
        let input=Bytes::from(vec![7;MAX_PAYLOAD]);
        let mut address=None;
        for _ in 0..100 {
            // Retain input so the FULL encoder cannot mutate it.
            let frame=encoder.prepare(DATA,1,Protection::Full,input.clone()).unwrap();
            if let Some(ptr)=address {assert_eq!(frame.payload.as_ptr(),ptr);}
            address=Some(frame.payload.as_ptr());
            encoder.reclaim(frame);
            assert!(input.iter().all(|b|*b==7));
        }
    }
}
