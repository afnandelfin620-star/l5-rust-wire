use bytes::Bytes;
use l5_wire::{codecs, Protection, DATA, PING};
use std::{
    collections::VecDeque,
    io,
    task::{Context, Poll},
};

struct Input {
    chunks: VecDeque<Bytes>,
    pending: bool,
}
fn read(input: &mut Input, cx: &mut Context<'_>) -> Poll<io::Result<Bytes>> {
    // Force cancellation/resumption between chunks, just as Transport::poll_next.
    if input.pending {
        input.pending = false;
        cx.waker().wake_by_ref();
        return Poll::Pending;
    }
    input.pending = true;
    Poll::Ready(Ok(input.chunks.pop_front().unwrap_or_default()))
}
#[tokio::test]
async fn shared_payload_no_copy_and_full_frames_authenticated() {
    for split in [1, 5, 35, 36, 37, 16384, 65536] {
        let (mut rx, _) = codecs(&[9; 32], false).unwrap();
        let (_, mut tx) = codecs(&[9; 32], true).unwrap();
        let payload = vec![0x83; 65539];
        let mut wire = tx
            .encode(DATA, 42, Protection::TlsPassthrough, &payload)
            .unwrap();
        wire.extend(tx.encode(PING, 0, Protection::Full, b"probe").unwrap());
        let owner = Bytes::from(wire);
        let base = owner.as_ptr() as usize;
        let mut input = Input {
            chunks: (0..owner.len())
                .step_by(split)
                .map(|i| owner.slice(i..(i + split).min(owner.len())))
                .collect(),
            pending: true,
        };
        let mut offset = 0;
        let mut held = Vec::new();
        while offset < payload.len() {
            // Drop a pending future, then reconstruct it: partial state belongs to Decoder.
            let m = futures::future::poll_fn(|cx| {
                let future = rx.read_owned(&mut input, read);
                tokio::pin!(future);
                std::future::Future::poll(future.as_mut(), cx)
            })
            .await
            .unwrap();
            assert_eq!(m.cmd, DATA);
            assert_eq!(m.id, 42);
            assert_eq!(m.payload.as_ptr() as usize, base + 36 + offset);
            assert!(m.payload.iter().all(|b| *b == 0x83));
            offset += m.payload.len();
            held.push(m.payload);
        }
        let m = rx.read_owned(&mut input, read).await.unwrap();
        assert_eq!(m.cmd, PING);
        assert_eq!(&m.payload[..], b"probe");
        assert_eq!(held.iter().map(|b| b.len()).sum::<usize>(), payload.len());
    }
    let (mut rx, _) = codecs(&[9; 32], false).unwrap();
    let (_, mut tx) = codecs(&[9; 32], true).unwrap();
    let mut bad = tx
        .encode(DATA, 1, Protection::Full, b"must not deliver before auth")
        .unwrap();
    *bad.last_mut().unwrap() ^= 1;
    let mut input = Input {
        chunks: bad.into_iter().map(|b| Bytes::from(vec![b])).collect(),
        pending: true,
    };
    assert!(rx.read_owned(&mut input, read).await.is_err());
    assert!(rx.read_owned(&mut input, read).await.is_err());
}
#[tokio::test]
async fn shared_header_rejected_before_payload_and_truncation_sticky() {
    let (_, mut tx) = codecs(&[3; 32], true).unwrap();
    let wire = tx
        .encode(DATA, 1, Protection::TlsPassthrough, b"123456789")
        .unwrap();
    for end in 0..wire.len() {
        let (mut rx, _) = codecs(&[3; 32], false).unwrap();
        let mut input = Input {
            chunks: VecDeque::from([Bytes::copy_from_slice(&wire[..end])]),
            pending: true,
        };
        // Passthrough may emit available ciphertext first; it must never accept a truncated frame as complete.
        loop {
            if rx.read_owned(&mut input, read).await.is_err() {
                break;
            }
        }
        assert!(rx.read_owned(&mut input, read).await.is_err());
    }
    for at in 0..36 {
        let (mut rx, _) = codecs(&[3; 32], false).unwrap();
        let mut bad = wire.clone();
        bad[at] ^= 1;
        let mut input = Input {
            chunks: VecDeque::from([Bytes::from(bad)]),
            pending: false,
        };
        assert!(rx.read_owned(&mut input, read).await.is_err());
    }
}
