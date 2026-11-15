//! Inner TLS record headers of passthrough payloads never appear on the wire,
//! and both receivers restore the exact byte stream.
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use l5_wire::{
    fixed::Hooks,
    transport::{Message, Transport},
};
use std::{
    io,
    ops::Range,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Default)]
struct Wire(Arc<Mutex<Vec<u8>>>);
impl AsyncRead for Wire {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Wire {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        // Short writes exercise partial progress across masked slices.
        let n = b.len().min(1000);
        self.0.lock().unwrap().extend_from_slice(&b[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Input(Bytes);
impl AsyncRead for Input {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let n = self.0.len().min(buf.remaining()).min(777);
        let chunk = self.0.split_to(n);
        buf.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Input {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
fn read(s: &mut Input, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
    let n = s.0.len().min(buf.remaining()).min(1500);
    buf.put_slice(&s.0.split_to(n));
    Poll::Ready(Ok(()))
}
fn process(_: &mut Input, buf: &mut [u8], spans: &mut Vec<Range<usize>>) -> anyhow::Result<usize> {
    spans.clear();
    let mut offset = 0;
    while buf.len() - offset >= 5 {
        let n = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        if buf.len() - offset < 5 + n {
            break;
        }
        spans.push(offset + 5..offset + 5 + n);
        offset += 5 + n;
    }
    Ok(offset)
}
fn records(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for b in wire.chunks(16384) {
        out.extend([23, 3, 3, (b.len() >> 8) as u8, b.len() as u8]);
        out.extend_from_slice(b);
    }
    out
}

fn hello() -> Vec<u8> {
    let mut v = vec![22, 3, 3, 0, 38, 1, 0, 0, 34, 3, 3];
    v.extend([0x55; 32]);
    v
}
/// Application TLS stream after the handshake: tiny, medium and maximum records.
fn inner_stream() -> Vec<u8> {
    let mut sizes = vec![17, 30, 16401, 5000, 18432, 1];
    sizes.extend(std::iter::repeat_n(17, 40)); // > 16 headers in one payload
    sizes.extend([300, 16401, 16401, 2000]);
    let mut v = Vec::new();
    for n in sizes {
        v.extend([23, 3, 3, (n >> 8) as u8, n as u8]);
        v.extend(std::iter::repeat_n(0x55, n));
    }
    v
}

#[tokio::test]
async fn inner_headers_masked_and_restored_by_both_receivers() {
    let root = [5u8; 32];
    let id = 0x10001;
    let stream = inner_stream();
    let shared = Bytes::from(stream.clone()); // retained: payloads are not unique
    let wire = Wire::default();
    let mut tx = Transport::new(wire.clone(), &root, true).unwrap();
    tx.send(Message::Data { id, payload: Bytes::from(hello()) }).await.unwrap();
    let cuts = [1usize, 2, 3, 7, 100, 997, 4096, 30000, 900, 65536];
    let (mut at, mut i) = (0, 0);
    while at < stream.len() {
        let n = cuts[i % cuts.len()].min(stream.len() - at);
        let payload = if i % 2 == 0 {
            shared.slice(at..at + n)
        } else {
            Bytes::copy_from_slice(&stream[at..at + n])
        };
        tx.send(Message::Data { id, payload }).await.unwrap();
        at += n;
        i += 1;
    }
    let wire = wire.0.lock().unwrap().clone();
    // Bodies are 0x55, so 17 03 03 could only come from an unmasked header.
    assert!(!wire.windows(3).any(|w| w == [23, 3, 3]), "plaintext inner TLS header on wire");

    // Contiguous decoder.
    let mut rx = Transport::new(Input(wire.clone().into()), &root, false).unwrap();
    let mut got = Vec::new();
    while got.len() < hello().len() + stream.len() {
        let Message::Binary(b) = rx.next().await.unwrap().unwrap() else { panic!("data expected") };
        assert_eq!(b[0], 1);
        got.extend_from_slice(&b[5..]);
    }
    assert_eq!(&got[..hello().len()], &hello()[..]);
    assert_eq!(&got[hello().len()..], &stream[..]);

    // Fixed receive buffer: payload ranges may be split across outer records.
    let mut rx = Transport::new_fixed(
        Input(records(&wire).into()),
        &root,
        false,
        1024 * 1024,
        &[],
        Hooks { read, process, closed: |_| false },
    )
    .unwrap();
    let mut got = Vec::new();
    while got.len() < hello().len() + stream.len() {
        let Message::DataFrame { id: got_id, payload } = rx.next().await.unwrap().unwrap() else {
            panic!("data expected")
        };
        assert_eq!(got_id, id);
        for c in payload.chunks() {
            got.extend_from_slice(c);
        }
    }
    assert_eq!(&got[hello().len()..], &stream[..]);
}
