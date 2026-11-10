//! Fixed receive storage owned by the tunnel reader. No slab rotation, no
//! receive-buffer growth. Payload leases prevent the next read until delivery
//! finishes; the same allocation is reclaimed, never replaced.
use crate::transport::Message;
use crate::{keys, nonce, Keys, Protection, DATA, HEADER, MAX_PAYLOAD, TAG};
use anyhow::{ensure, Result};
use bytes::Bytes;
use ring::aead;
use std::{
    collections::VecDeque,
    io,
    ops::Range,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::io::ReadBuf;

#[derive(Debug, PartialEq, Eq)]
pub struct Payload {
    storage: Arc<Box<[u8]>>,
    ranges: Vec<Range<usize>>,
    len: usize,
}
impl Payload {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.ranges.iter().map(|r| &self.storage[r.clone()])
    }
}
pub struct Hooks<S> {
    pub read: fn(&mut S, &mut Context<'_>, &mut ReadBuf<'_>) -> Poll<io::Result<()>>,
    pub process: fn(&mut S, &mut [u8], &mut Vec<Range<usize>>) -> Result<usize>,
    pub closed: fn(&S) -> bool,
}
#[derive(Clone, Copy)]
struct Meta {
    cmd: u8,
    id: u32,
    mode: Protection,
    len: usize,
}
pub struct Reader {
    storage: Arc<Box<[u8]>>,
    used: usize,
    tls_cursor: usize,
    segments: VecDeque<Range<usize>>,
    spans: Vec<Range<usize>>,
    header: [u8; HEADER + TAG],
    header_used: usize,
    meta: Option<Meta>,
    ranges: Vec<Range<usize>>,
    collected: usize,
    keys: Keys,
    seq: u64,
    failed: bool,
    #[cfg(feature = "size-diagnostics")]
    pub compactions: u64,
}
impl Reader {
    pub fn new(root: &[u8], client: bool, capacity: usize, initial: &[u8]) -> Result<Self> {
        ensure!(
            (1024 * 1024..=8 * 1024 * 1024).contains(&capacity),
            "invalid fixed receive capacity"
        );
        ensure!(
            initial.len() <= capacity,
            "TLS handshake read-ahead overflow"
        );
        let mut storage = vec![0u8; capacity].into_boxed_slice(); // Once, at connection creation.
        storage[..initial.len()].copy_from_slice(initial);
        #[cfg(feature = "size-diagnostics")]
        crate::diagnostics::record(7, capacity);
        Ok(Self {
            storage: Arc::new(storage),
            used: initial.len(),
            tls_cursor: 0,
            segments: VecDeque::new(),
            spans: Vec::new(),
            header: [0; HEADER + TAG],
            header_used: 0,
            meta: None,
            ranges: Vec::new(),
            collected: 0,
            keys: keys(root, if client { "server" } else { "client" })?,
            seq: 0,
            failed: false,
            #[cfg(feature = "size-diagnostics")]
            compactions: 0,
        })
    }
    pub fn poll_next<S>(
        &mut self,
        io: &mut S,
        hooks: &Hooks<S>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Message>> {
        if self.failed {
            return Poll::Ready(Err(anyhow::anyhow!("fixed receiver failed")));
        }
        let result = self.poll_inner(io, hooks, cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
    fn poll_inner<S>(
        &mut self,
        io: &mut S,
        hooks: &Hooks<S>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Message>> {
        macro_rules! poll_ensure {
            ($condition:expr,$message:expr) => {
                if !$condition {
                    return Poll::Ready(Err(anyhow::anyhow!($message)));
                }
            };
        }
        macro_rules! poll_bail {
            ($message:expr) => {
                return Poll::Ready(Err(anyhow::anyhow!($message)))
            };
        }
        // The caller must finish dispatch (including an async blocked write)
        // before requesting the next message. Never allocate around a live lease.
        poll_ensure!(
            Arc::strong_count(&self.storage) == 1,
            "previous payload still borrowed"
        );
        poll_ensure!(self.seq < u64::MAX, "sequence exhausted");
        let mut iterations = 0;
        loop {
            if self.meta.is_none() && self.header_used == self.header.len() {
                let h = self
                    .keys
                    .header
                    .open_in_place(nonce(self.seq), aead::Aad::empty(), &mut self.header)
                    .map_err(|_| anyhow::anyhow!("header authentication failed"))?;
                poll_ensure!(h[0] == 2 && h[3] == 0, "frame version/reserved");
                poll_ensure!(
                    u64::from_be_bytes(h[8..16].try_into()?) == self.seq,
                    "sequence mismatch"
                );
                let mode = match h[2] {
                    0 => Protection::Full,
                    1 => Protection::TlsPassthrough,
                    _ => poll_bail!("unknown mode"),
                };
                let cmd = h[1];
                poll_ensure!(
                    (crate::HELLO..=crate::PONG).contains(&cmd),
                    "unknown command"
                );
                poll_ensure!(
                    matches!(cmd, crate::ECHO | DATA) || mode == Protection::Full,
                    "control protection"
                );
                let len = u32::from_be_bytes(h[16..20].try_into()?) as usize;
                poll_ensure!(len <= MAX_PAYLOAD, "oversized frame");
                self.meta = Some(Meta {
                    cmd,
                    id: u32::from_be_bytes(h[4..8].try_into()?),
                    mode,
                    len,
                });
            }
            if let Some(m) = self.meta {
                let total = m.len + if m.mode == Protection::Full { TAG } else { 0 };
                if self.collected == total {
                    return Poll::Ready(self.finish(m));
                }
            }
            if let Some(mut range) = self.segments.pop_front() {
                if let Some(m) = self.meta {
                    let total = m.len + if m.mode == Protection::Full { TAG } else { 0 };
                    let n = (total - self.collected).min(range.len());
                    self.ranges.push(range.start..range.start + n);
                    self.collected += n;
                    range.start += n;
                } else {
                    let n = (self.header.len() - self.header_used).min(range.len());
                    self.header[self.header_used..self.header_used + n]
                        .copy_from_slice(&self.storage[range.start..range.start + n]);
                    self.header_used += n;
                    range.start += n;
                }
                if !range.is_empty() {
                    self.segments.push_front(range);
                }
                continue;
            }
            if iterations >= 64 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            iterations += 1;
            let offset = self.tls_cursor;
            let consumed = (hooks.process)(
                io,
                &mut Arc::get_mut(&mut self.storage).unwrap()[offset..self.used],
                &mut self.spans,
            )?;
            poll_ensure!(
                consumed <= self.used - offset,
                "TLS consumed beyond receive buffer"
            );
            for span in self.spans.drain(..) {
                poll_ensure!(
                    span.start <= span.end && span.end <= consumed,
                    "TLS payload range outside consumed input"
                );
                if !span.is_empty() {
                    #[cfg(feature = "size-diagnostics")]
                    crate::diagnostics::record(3, span.len());
                    self.segments
                        .push_back(offset + span.start..offset + span.end);
                }
            }
            self.tls_cursor += consumed;
            if !self.segments.is_empty() {
                continue;
            }
            if (hooks.closed)(io) {
                poll_bail!("TLS peer closed");
            }
            if self.used == self.storage.len() {
                self.compact()?;
            }
            let mut read = ReadBuf::new(&mut Arc::get_mut(&mut self.storage).unwrap()[self.used..]);
            ready!((hooks.read)(io, cx, &mut read))?;
            let n = read.filled().len();
            poll_ensure!(n > 0, "TLS socket EOF");
            #[cfg(feature = "size-diagnostics")]
            crate::diagnostics::record(6, n);
            self.used += n;
        }
    }
    fn compact(&mut self) -> Result<()> {
        // Unfinished message ranges and incomplete TLS input are the only live
        // bytes. Completed messages have already been copied into the target.
        let keep = self
            .ranges
            .first()
            .map(|r| r.start)
            .unwrap_or(self.tls_cursor)
            .min(self.tls_cursor);
        ensure!(keep > 0, "message cannot fit fixed receive buffer");
        #[cfg(feature = "size-diagnostics")]
        crate::diagnostics::record(8, self.used - keep);
        Arc::get_mut(&mut self.storage)
            .unwrap()
            .copy_within(keep..self.used, 0);
        self.used -= keep;
        self.tls_cursor -= keep;
        for r in &mut self.ranges {
            r.start -= keep;
            r.end -= keep;
        }
        for r in &mut self.segments {
            r.start -= keep;
            r.end -= keep;
        }
        #[cfg(feature = "size-diagnostics")]
        {
            self.compactions += 1;
        }
        Ok(())
    }
    fn finish(&mut self, m: Meta) -> Result<Message> {
        if m.mode == Protection::Full {
            // GCM requires contiguous mutable ciphertext. Only FULL messages
            // gather in place in this SAME buffer; passthrough never does.
            let start = self.ranges.first().map(|r| r.start).unwrap_or(0);
            let buffer = Arc::get_mut(&mut self.storage).unwrap();
            let mut end = start;
            for r in &self.ranges {
                if r.start != end {
                    buffer.copy_within(r.clone(), end);
                }
                end += r.len();
            }
            self.keys
                .full
                .open_in_place(
                    nonce(self.seq),
                    aead::Aad::from(&self.header[..HEADER]),
                    &mut buffer[start..end],
                )
                .map_err(|_| anyhow::anyhow!("payload authentication failed"))?;
            self.ranges.clear();
            if m.len > 0 {
                self.ranges.push(start..start + m.len);
            }
        }
        #[cfg(feature = "size-diagnostics")]
        crate::diagnostics::record(
            if m.cmd == DATA {
                if m.mode == Protection::Full {
                    0
                } else {
                    1
                }
            } else {
                2
            },
            m.len,
        );
        let result = if m.cmd == DATA {
            Message::DataFrame {
                id: m.id,
                payload: Payload {
                    storage: self.storage.clone(),
                    ranges: std::mem::take(&mut self.ranges),
                    len: m.len,
                },
            }
        } else {
            // Control/DNS/UDP messages may outlive the read task. They retain
            // only their small payload, never the 4/8 MiB receive allocation.
            let mut data = Vec::with_capacity(m.len);
            for r in &self.ranges {
                data.extend_from_slice(&self.storage[r.clone()]);
            }
            let b = Bytes::from(data);
            match m.cmd {
                crate::L5 => Message::Binary(b),
                crate::PING => Message::Ping(b),
                crate::PONG => Message::Pong(b),
                crate::CLOSE => Message::Close(None),
                _ => anyhow::bail!("invalid tunnel command"),
            }
        };
        self.ranges.clear();
        self.meta = None;
        self.header_used = 0;
        self.collected = 0;
        self.seq += 1;
        Ok(result)
    }
}
