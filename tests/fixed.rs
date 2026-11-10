use bytes::Bytes;
use futures::StreamExt;
use l5_wire::{
    codecs,
    fixed::Hooks,
    transport::{Message, Transport},
    Protection, DATA,
};
use std::{
    collections::HashSet,
    io,
    ops::Range,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
struct Input {
    data: Bytes,
    reads: Arc<Mutex<Vec<(usize, usize)>>>,
    yield_next: bool,
}
fn read(s: &mut Input, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
    if s.yield_next {
        s.yield_next = false;
        cx.waker().wake_by_ref();
        return Poll::Pending;
    }
    s.yield_next = true;
    let n = s.data.len().min(buf.remaining()).min(997);
    let p = buf.initialize_unfilled().as_ptr() as usize;
    s.reads.lock().unwrap().push((p, buf.remaining()));
    buf.put_slice(&s.data.split_to(n));
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
fn records(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for b in wire.chunks(16384) {
        out.extend([126, 3, 3, (b.len() >> 8) as u8, b.len() as u8]);
        out.extend_from_slice(b);
    }
    out
}
#[tokio::test]
async fn one_allocation_across_many_wraps_and_full_decryption() {
    let (_, mut tx) = codecs(&[9; 32], true).unwrap();
    let mut wire = Vec::new();
    for i in 0..100u32 {
        wire.extend(
            tx.encode(
                DATA,
                i,
                if i % 3 == 0 {
                    Protection::Full
                } else {
                    Protection::TlsPassthrough
                },
                &vec![i as u8; 256 * 1024],
            )
            .unwrap(),
        );
    }
    let reads = Arc::new(Mutex::new(Vec::new()));
    let input = Input {
        data: records(&wire).into(),
        reads: reads.clone(),
        yield_next: true,
    };
    let capacity = 1024 * 1024;
    let mut t = Transport::new_fixed(
        input,
        &[9; 32],
        false,
        capacity,
        &[],
        Hooks {
            read,
            process,
            closed: |_| false,
        },
    )
    .unwrap();
    let mut ends = HashSet::new();
    for i in 0..100u32 {
        let Message::DataFrame { id, payload } = t.next().await.unwrap().unwrap() else {
            panic!("not borrowed frame")
        };
        assert_eq!(id, i);
        assert_eq!(payload.len(), 256 * 1024);
        assert!(payload.chunks().all(|b| b.iter().all(|v| *v == i as u8)));
        let before = reads.lock().unwrap().len();
        tokio::task::yield_now().await;
        assert_eq!(
            before,
            reads.lock().unwrap().len(),
            "reading while dispatch is suspended"
        );
        // Explicitly release the lease before next message: exactly the application backpressure contract.
        drop(payload);
    }
    for &(p, n) in reads.lock().unwrap().iter() {
        ends.insert(p + n);
    }
    assert_eq!(ends.len(), 1, "socket reads moved to a new allocation");
    assert!(reads.lock().unwrap().len() > 20000);
}
#[tokio::test]
async fn retained_payload_cannot_be_overwritten() {
    let (_, mut tx) = codecs(&[3; 32], true).unwrap();
    let mut wire = tx
        .encode(DATA, 1, Protection::TlsPassthrough, b"keep")
        .unwrap();
    wire.extend(
        tx.encode(DATA, 2, Protection::TlsPassthrough, b"next")
            .unwrap(),
    );
    let input = Input {
        data: records(&wire).into(),
        reads: Default::default(),
        yield_next: false,
    };
    let mut t = Transport::new_fixed(
        input,
        &[3; 32],
        false,
        1024 * 1024,
        &[],
        Hooks {
            read,
            process,
            closed: |_| false,
        },
    )
    .unwrap();
    let Message::DataFrame { payload, .. } = t.next().await.unwrap().unwrap() else {
        panic!()
    };
    assert!(t.next().await.unwrap().is_err());
    assert_eq!(
        payload.chunks().flatten().copied().collect::<Vec<_>>(),
        b"keep"
    );
}
