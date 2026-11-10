use crate::{sniff::TlsRecords, Decoder, Encoded, Encoder, Protection};
use anyhow::{ensure, Result};
use bytes::Bytes;
use futures::{Sink, Stream};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    DataFrame {
        id: u32,
        payload: crate::fixed::Payload,
    },
    Data {
        id: u32,
        payload: Bytes,
    },
    DataChunks {
        id: u32,
        chunks: Vec<Bytes>,
    },
    Binary(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close(Option<()>),
}
impl Message {
    pub fn into_data(self) -> Bytes {
        match self {
            Self::Binary(b) | Self::Ping(b) | Self::Pong(b) | Self::Data { payload: b, .. } => b,
            Self::DataFrame { payload, .. } => {
                let mut b = bytes::BytesMut::with_capacity(payload.len());
                for c in payload.chunks() {
                    b.extend_from_slice(c);
                }
                b.freeze()
            }
            Self::DataChunks { chunks, .. } => {
                // Convenience conversion only. Production consumers use vectored writes.
                let mut b = bytes::BytesMut::with_capacity(chunks.iter().map(Bytes::len).sum());
                for c in chunks {
                    b.extend_from_slice(&c);
                }
                b.freeze()
            }
            Self::Close(_) => Bytes::new(),
        }
    }
}
enum Phase {
    Detecting(TlsRecords),
    Full,
    Passthrough,
}
struct Session {
    id: u32,
    phase: Phase,
}
impl Session {
    fn protection(&mut self, payload: &[u8]) -> Protection {
        match &mut self.phase {
            Phase::Passthrough => Protection::TlsPassthrough,
            Phase::Full => Protection::Full,
            Phase::Detecting(sniff) => {
                let pass = sniff.encrypted_chunk(payload);
                if sniff.passthrough {
                    self.phase = Phase::Passthrough;
                } else if sniff.failed() {
                    self.phase = Phase::Full;
                }
                if pass {
                    Protection::TlsPassthrough
                } else {
                    Protection::Full
                }
            }
        }
    }
}

/// Transport framing shared by Android and server. No WebSocket codec and no
/// per-request forwarding task. TLS stream retains its optimized IO buffers.
pub struct Transport<S> {
    io: S,
    read_owned: Option<fn(&mut S, &mut Context<'_>) -> Poll<std::io::Result<Bytes>>>,
    rx: Decoder,
    tx: Encoder,
    pending: Option<Encoded>,
    pongs: VecDeque<Bytes>,
    classifiers: HashMap<u16, Session>,
    closed: bool,
    receive_chunks: Vec<Bytes>,
    fixed: Option<(crate::fixed::Reader, crate::fixed::Hooks<S>)>,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    pub fn new(io: S, root: &[u8], client: bool) -> Result<Self> {
        let (mut rx, tx) = crate::codecs(root, client)?;
        rx.legacy_data = true;
        Ok(Self {
            io,
            read_owned: None,
            rx,
            tx,
            pending: None,
            pongs: VecDeque::new(),
            classifiers: HashMap::new(),
            closed: false,
            receive_chunks: Vec::new(),
            fixed: None,
        })
    }
    pub fn new_owned(
        io: S,
        root: &[u8],
        client: bool,
        read: fn(&mut S, &mut Context<'_>) -> Poll<std::io::Result<Bytes>>,
    ) -> Result<Self> {
        let mut t = Self::new(io, root, client)?;
        t.read_owned = Some(read);
        Ok(t)
    }
    pub fn new_fixed(
        io: S,
        root: &[u8],
        client: bool,
        capacity: usize,
        initial: &[u8],
        hooks: crate::fixed::Hooks<S>,
    ) -> Result<Self> {
        let mut t = Self::new(io, root, client)?;
        t.fixed = Some((
            crate::fixed::Reader::new(root, client, capacity, initial)?,
            hooks,
        ));
        Ok(t)
    }
    fn protection(&mut self, id: u32, payload: &[u8]) -> Protection {
        let slot = self
            .classifiers
            .entry(id as u16)
            .or_insert_with(|| Session {
                id,
                phase: Phase::Detecting(TlsRecords::default()),
            });
        if slot.id != id {
            *slot = Session {
                id,
                phase: Phase::Detecting(TlsRecords::default()),
            };
        }
        slot.protection(payload)
    }
    fn control(&mut self, b: &[u8], outgoing: bool) {
        if b.len() < 5 {
            return;
        }
        let idx = u16::from_le_bytes([b[1], b[2]]);
        let id = u32::from(idx) | (u32::from(u16::from_le_bytes([b[3], b[4]])) << 16);
        if b[0] == 2 {
            self.classifiers.remove(&idx); // New session, including same-tag reuse.
        } else if matches!(b[0], 3 | 6) || (outgoing && matches!(b[0], 4 | 5)) {
            if self.classifiers.get(&idx).is_some_and(|s| s.id == id) {
                self.classifiers.remove(&idx);
            }
        }
        // Incoming half-close does not reset our independently active direction.
    }
    fn prepare(&mut self, msg: Message) -> Result<Encoded> {
        let (cmd, id, mode, payload) = match msg {
            Message::DataFrame { .. } | Message::DataChunks { .. } => {
                anyhow::bail!("DataChunks is a receive-only complete frame")
            }
            Message::Data { id, payload } => {
                let mode = self.protection(id, &payload);
                (crate::DATA, id, mode, payload)
            }
            Message::Binary(b) => {
                if b.len() >= 5 && b[0] == 1 {
                    let id = u32::from(u16::from_le_bytes([b[1], b[2]]))
                        | (u32::from(u16::from_le_bytes([b[3], b[4]])) << 16);
                    let data = b.slice(5..);
                    let mode = self.protection(id, &data);
                    (crate::DATA, id, mode, data)
                } else {
                    self.control(&b, true);
                    (crate::L5, 0, Protection::Full, b)
                }
            }
            Message::Ping(b) => (crate::PING, 0, Protection::Full, b),
            Message::Pong(b) => {
                self.pongs.retain(|p| p != &b);
                (crate::PONG, 0, Protection::Full, b)
            }
            Message::Close(_) => (crate::CLOSE, 0, Protection::Full, Bytes::new()),
        };
        #[cfg(feature = "size-diagnostics")]
        if cmd == crate::DATA {
            crate::diagnostics::record(5, payload.len());
        }
        self.tx.prepare(cmd, id, mode, payload)
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(p) = self.pending.as_mut() {
            ready!(p.poll_write(&mut self.io, cx))?;
            let completed = self.pending.take().unwrap();
            self.tx.reclaim(completed);
        }
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Message> for Transport<S> {
    type Error = anyhow::Error;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.drain(cx)
    }
    fn start_send(mut self: Pin<&mut Self>, msg: Message) -> Result<()> {
        ensure!(self.pending.is_none(), "sink not ready");
        self.pending = Some(self.prepare(msg)?);
        Ok(())
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        ready!(self.drain(cx))?;
        while let Some(pong) = self.pongs.pop_front() {
            self.pending = Some(self.prepare(Message::Pong(pong))?);
            ready!(self.drain(cx))?;
        }
        Poll::Ready(ready!(Pin::new(&mut self.io).poll_flush(cx)).map_err(Into::into))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Poll::Ready(ready!(Pin::new(&mut self.io).poll_shutdown(cx)).map_err(Into::into))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> Stream for Transport<S> {
    type Item = Result<Message>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }
        if !self.pongs.is_empty() {
            if let Err(e) = ready!(self.as_mut().poll_flush(cx)) {
                self.closed = true;
                return Poll::Ready(Some(Err(e)));
            }
        }
        if self.fixed.is_some() {
            let result = {
                let this = &mut *self;
                let (reader, hooks) = this.fixed.as_mut().unwrap();
                ready!(reader.poll_next(&mut this.io, hooks, cx))
            };
            let message = match result {
                Ok(m) => m,
                Err(e) => {
                    self.closed = true;
                    return Poll::Ready(Some(Err(e)));
                }
            };
            match &message {
                Message::Binary(b) => self.control(b, false),
                Message::Ping(b) => {
                    if self.pongs.len() >= 32 {
                        self.closed = true;
                        return Poll::Ready(Some(Err(anyhow::anyhow!("too many pings"))));
                    }
                    self.pongs.push_back(b.clone());
                }
                Message::Close(_) => self.closed = true,
                _ => {}
            }
            return Poll::Ready(Some(Ok(message)));
        }
        let mut slices_this_poll = 0;
        loop {
            let result = {
                let this = &mut *self;
                let fut = async {
                    match this.read_owned {
                        Some(read) => this.rx.read_owned(&mut this.io, read).await,
                        None => this.rx.read(&mut this.io).await,
                    }
                };
                tokio::pin!(fut);
                ready!(fut.poll(cx))
            };
            let frame = match result {
                Ok(m) => m,
                Err(e) => {
                    self.closed = true;
                    self.receive_chunks.clear();
                    return Poll::Ready(Some(Err(e)));
                }
            };
            if frame.cmd == crate::L5 {
                self.control(&frame.payload, false);
            }
            let message = match frame.cmd {
                crate::DATA
                    if self.read_owned.is_some()
                        && frame.protection == Protection::TlsPassthrough =>
                {
                    if !frame.payload.is_empty() {
                        self.receive_chunks.push(frame.payload);
                    }
                    if !self.rx.frame_complete() {
                        slices_this_poll += 1;
                        if slices_this_poll >= 64 {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        continue;
                    }
                    // Preserve all receive slab owners; gather descriptors, not bytes.
                    Message::DataChunks {
                        id: frame.id,
                        chunks: std::mem::take(&mut self.receive_chunks),
                    }
                }
                crate::DATA | crate::L5 => Message::Binary(frame.payload),
                crate::PING => {
                    if self.pongs.len() >= 32 {
                        self.closed = true;
                        return Poll::Ready(Some(Err(anyhow::anyhow!("too many pings"))));
                    }
                    self.pongs.push_back(frame.payload.clone());
                    Message::Ping(frame.payload)
                }
                crate::PONG => Message::Pong(frame.payload),
                crate::CLOSE => {
                    self.closed = true;
                    Message::Close(None)
                }
                _ => {
                    self.closed = true;
                    return Poll::Ready(Some(Err(anyhow::anyhow!("invalid tunnel command"))));
                }
            };
            return Poll::Ready(Some(Ok(message)));
        }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    fn hello() -> Vec<u8> {
        let mut v = vec![22, 3, 3, 0, 38, 1, 0, 0, 34, 3, 3];
        v.extend([0; 32]);
        v
    }
    fn control(cmd: u8, id: u32) -> Vec<u8> {
        vec![
            cmd,
            id as u8,
            (id >> 8) as u8,
            (id >> 16) as u8,
            (id >> 24) as u8,
        ]
    }
    fn transport() -> Transport<tokio::io::DuplexStream> {
        Transport::new(tokio::io::duplex(4096).0, &[1; 32], true).unwrap()
    }
    #[test]
    fn latch_bypasses_parser_and_reuse_resets_both_control_directions() {
        for outgoing in [true, false] {
            let mut t = transport();
            let id = 0x10001;
            assert_eq!(t.protection(id, &hello()), Protection::Full);
            assert_eq!(
                t.protection(id, &[23, 3, 3, 0, 20]),
                Protection::TlsPassthrough
            );
            assert!(matches!(t.classifiers[&1].phase, Phase::Passthrough));
            for _ in 0..100 {
                assert_eq!(
                    t.protection(id, b"not a TLS record; no sniff"),
                    Protection::TlsPassthrough
                );
            }
            t.control(&control(4, id), false);
            assert_eq!(t.protection(id, b"body"), Protection::TlsPassthrough);
            t.control(&control(6, 0x20001), outgoing);
            assert_eq!(t.protection(id, b"body"), Protection::TlsPassthrough);
            t.control(&control(3, id), outgoing);
            assert!(!t.classifiers.contains_key(&1));
            assert_eq!(t.protection(id, b"GET /"), Protection::Full);
            t.control(&control(2, id), outgoing);
            assert_eq!(t.protection(id, &hello()), Protection::Full);
            assert_eq!(
                t.protection(id, &[23, 3, 3, 0, 20]),
                Protection::TlsPassthrough
            );
            assert_eq!(t.protection(0x20001, b"GET /"), Protection::Full);
            assert_eq!(t.classifiers.len(), 1);
        }
    }
    #[test]
    fn mixed_transition_and_opposite_direction_stay_protected() {
        let mut t = transport();
        let mut other = transport();
        let id = 7;
        let mut mixed = hello();
        mixed.extend([23, 3, 3, 0, 20]);
        mixed.extend([8; 20]);
        assert_eq!(t.protection(id, &mixed), Protection::Full);
        assert_eq!(
            t.protection(id, b"continuation"),
            Protection::TlsPassthrough
        );
        assert_eq!(other.protection(id, b"plaintext"), Protection::Full);
        assert_eq!(other.protection(id, &mixed), Protection::Full);
    }
}
