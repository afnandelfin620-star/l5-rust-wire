//! Several queued frames leave in one vectored write; partial writes resume
//! inside the batch without corrupting the frame stream.
use bytes::Bytes;
use futures::SinkExt;
use l5_wire::{codecs, transport::{Message, Transport}, DATA};
use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Log {
    wire: Vec<u8>,
    writes: usize,
}
struct Rec {
    log: Arc<Mutex<Log>>,
    limit: usize,
}
impl AsyncRead for Rec {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Rec {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_vectored(cx, &[IoSlice::new(b)])
    }
    fn poll_write_vectored(self: Pin<&mut Self>, _: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let mut log = self.log.lock().unwrap();
        log.writes += 1;
        let mut n = 0;
        for b in bufs {
            let take = b.len().min(self.limit - n);
            log.wire.extend_from_slice(&b[..take]);
            n += take;
            if n == self.limit {
                break;
            }
        }
        Poll::Ready(Ok(n))
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
/// Immutable payload owner: forces the FULL encoder through its arena.
struct Owned(Vec<u8>);
impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
fn payload(i: usize, n: usize) -> Bytes {
    Bytes::from_owner(Owned(vec![i as u8; n]))
}
async fn run(limit: usize, frames: usize, size: usize) -> Log {
    let log = Arc::new(Mutex::new(Log::default()));
    let mut t = Transport::new(Rec { log: log.clone(), limit }, &[3; 32], true).unwrap();
    for i in 0..frames {
        t.feed(Message::Data { id: i as u32 + 1, payload: payload(i, size) }).await.unwrap();
    }
    t.flush().await.unwrap();
    let mut rx = codecs(&[3; 32], false).unwrap().0;
    let wire = std::mem::take(&mut log.lock().unwrap().wire);
    let mut input = &wire[..];
    for i in 0..frames {
        let m = rx.read(&mut input).await.unwrap();
        assert_eq!((m.cmd, m.id), (DATA, i as u32 + 1));
        assert_eq!(m.payload, vec![i as u8; size]);
    }
    assert!(input.is_empty());
    let writes = log.lock().unwrap().writes;
    Log { wire, writes }
}
#[tokio::test]
async fn frame_count_bound_batches_sixty_four_per_write() {
    assert_eq!(run(usize::MAX, 100, 1000).await.writes, 2);
}
#[tokio::test]
async fn byte_bound_closes_batch_after_crossing_256k() {
    // 100 KiB frames: the third crosses 256 KiB, the fourth starts a new batch.
    assert_eq!(run(usize::MAX, 4, 100 * 1024).await.writes, 2);
}
#[tokio::test]
async fn partial_writes_resume_mid_frame_and_mid_batch() {
    let log = run(777, 100, 1000).await;
    assert!(log.writes > 100);
}

