use bytes::Bytes;
use futures::{Stream, StreamExt};
use l5_wire::{
    codecs,
    transport::{Message, Transport},
    Protection, DATA,
};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
struct Input {
    chunks: VecDeque<Bytes>,
    yield_next: bool,
}
fn read(s: &mut Input, cx: &mut Context<'_>) -> Poll<io::Result<Bytes>> {
    if s.yield_next {
        s.yield_next = false;
        cx.waker().wake_by_ref();
        return Poll::Pending;
    }
    s.yield_next = true;
    Poll::Ready(Ok(s.chunks.pop_front().unwrap_or_default()))
}
impl AsyncRead for Input {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        unreachable!()
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
#[tokio::test]
async fn complete_once_zero_copy_pending_and_fin_order() {
    let (_, mut tx) = codecs(&[4; 32], true).unwrap();
    let n = 256 * 1024;
    let payload = vec![7; n];
    let mut wire = tx
        .encode(DATA, 91, Protection::TlsPassthrough, &payload)
        .unwrap();
    wire.extend(
        tx.encode(l5_wire::L5, 0, Protection::Full, &[5, 91, 0, 0, 0])
            .unwrap(),
    );
    let owner = Bytes::from(wire);
    let base = owner.as_ptr() as usize;
    let input = Input {
        chunks: (0..owner.len())
            .step_by(997)
            .map(|i| owner.slice(i..(i + 997).min(owner.len())))
            .collect(),
        yield_next: true,
    };
    let mut t = Transport::new_owned(input, &[4; 32], false, read).unwrap();
    let message = futures::future::poll_fn(|cx| Pin::new(&mut t).poll_next(cx))
        .await
        .unwrap()
        .unwrap();
    let Message::DataChunks { id, chunks } = message else {
        panic!("expected complete frame")
    };
    assert_eq!(id, 91);
    let mut offset = 0;
    for c in &chunks {
        assert_eq!(c.as_ptr() as usize, base + 36 + offset);
        assert!(c.iter().all(|b| *b == 7));
        offset += c.len();
    }
    assert_eq!(offset, n);
    assert_eq!(
        t.next().await.unwrap().unwrap(),
        Message::Binary(Bytes::from_static(&[5, 91, 0, 0, 0]))
    );
    assert!(chunks[0].iter().all(|b| *b == 7));
}
#[tokio::test]
async fn truncated_payload_never_delivers_partial_frame() {
    let (_, mut tx) = codecs(&[4; 32], true).unwrap();
    let mut wire = tx
        .encode(DATA, 91, Protection::TlsPassthrough, &vec![7; 65536])
        .unwrap();
    wire.pop();
    let input = Input {
        chunks: wire.chunks(1000).map(Bytes::copy_from_slice).collect(),
        yield_next: true,
    };
    let mut t = Transport::new_owned(input, &[4; 32], false, read).unwrap();
    assert!(t.next().await.unwrap().is_err());
    assert!(t.next().await.is_none());
}
