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
    Data { id: u32, payload: Bytes },
    Binary(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close(Option<()>),
}
impl Message {
    pub fn into_data(self) -> Bytes {
        match self {
            Self::Binary(b) | Self::Ping(b) | Self::Pong(b) | Self::Data { payload: b, .. } => b,
            Self::Close(_) => Bytes::new(),
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
    classifiers: HashMap<u32, TlsRecords>,
    closed: bool,
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
    fn prepare(&mut self, msg: Message) -> Result<Encoded> {
        let (cmd, id, mode, payload) = match msg {
            Message::Data { id, payload } => {
                let mode = if self
                    .classifiers
                    .entry(id)
                    .or_default()
                    .encrypted_chunk(&payload)
                {
                    Protection::TlsPassthrough
                } else {
                    Protection::Full
                };
                (crate::DATA, id, mode, payload)
            }
            Message::Binary(b) => {
                if b.len() >= 5 && b[0] == 1 {
                    let id = u32::from(u16::from_le_bytes([b[1], b[2]]))
                        | (u32::from(u16::from_le_bytes([b[3], b[4]])) << 16);
                    let data = b.slice(5..);
                    let c = self.classifiers.entry(id).or_default();
                    let mode = if c.encrypted_chunk(&data) {
                        Protection::TlsPassthrough
                    } else {
                        Protection::Full
                    };
                    (crate::DATA, id, mode, data)
                } else {
                    if b.len() >= 5 && matches!(b[0], 2 | 3 | 6) {
                        let id = u32::from(u16::from_le_bytes([b[1], b[2]]))
                            | (u32::from(u16::from_le_bytes([b[3], b[4]])) << 16);
                        self.classifiers.remove(&id);
                    }
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
        self.tx.prepare(cmd, id, mode, payload)
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(p) = self.pending.as_mut() {
            ready!(p.poll_write(&mut self.io, cx))?;
            self.pending = None;
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
                return Poll::Ready(Some(Err(e)));
            }
        };
        let message = match frame.cmd {
            crate::DATA
                if self.read_owned.is_some() && frame.protection == Protection::TlsPassthrough =>
            {
                Message::Data {
                    id: frame.id,
                    payload: frame.payload,
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
        Poll::Ready(Some(Ok(message)))
    }
}
