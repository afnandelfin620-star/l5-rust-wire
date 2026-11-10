use bytes::Bytes;
use l5_wire::{codecs, Protection, DATA, L5};
#[tokio::test]
async fn authenticate_modes_replay_tamper_and_cross_frame_substitution() {
    for mode in [Protection::Full, Protection::TlsPassthrough] {
        let (_, mut tx) = codecs(&[7; 32], true).unwrap();
        let first = tx.encode(DATA, 10, mode, b"secret payload").unwrap();
        let second = tx.encode(DATA, 11, mode, b"second payload").unwrap();
        for at in [0, 1, 2, 19, 20, 35] {
            let (mut rx, _) = codecs(&[7; 32], false).unwrap();
            let mut bad = first.clone();
            bad[at] ^= 1;
            assert!(rx.read(&mut &bad[..]).await.is_err());
            assert!(rx.read(&mut &first[..]).await.is_err());
        }
        let (mut rx, _) = codecs(&[7; 32], false).unwrap();
        assert_eq!(
            rx.read(&mut &first[..]).await.unwrap().payload.as_ref(),
            b"secret payload"
        );
        assert!(rx.read(&mut &first[..]).await.is_err());
        let (mut rx, _) = codecs(&[7; 32], false).unwrap();
        let mut swapped = first.clone();
        swapped[36..].copy_from_slice(&second[36..]);
        if mode == Protection::Full {
            assert!(rx.read(&mut &swapped[..]).await.is_err());
        } else {
            // Explicit contract: payload authenticity is delegated to application TLS.
            assert_eq!(
                rx.read(&mut &swapped[..]).await.unwrap().payload.as_ref(),
                b"second payload"
            );
        }
        let (mut wrong_direction, _) = codecs(&[7; 32], true).unwrap();
        assert!(wrong_direction.read(&mut &first[..]).await.is_err());
        let (mut wrong_session, _) = codecs(&[8; 32], false).unwrap();
        assert!(wrong_session.read(&mut &first[..]).await.is_err());
    }
}
#[tokio::test]
async fn payload_ownership_and_headroom_without_copy() {
    let (_, mut tx) = codecs(&[1; 32], true).unwrap();
    let owner = Bytes::from_owner(vec![17u8; 65536]);
    let ptr = owner.as_ptr();
    let encoded = tx
        .prepare(DATA, 0x22334455, Protection::TlsPassthrough, owner)
        .unwrap();
    assert_eq!(encoded.payload.as_ptr(), ptr);
    let data = Bytes::from(vec![22u8; 65536]);
    let ptr = data.as_ptr();
    let full = tx.prepare(DATA, 1, Protection::Full, data).unwrap();
    assert_eq!(full.payload.as_ptr(), ptr);
    let wire = encoded.to_vec();
    let (mut rx, _) = codecs(&[1; 32], false).unwrap();
    rx.legacy_data = true;
    let msg = rx.read(&mut &wire[..]).await.unwrap();
    assert_eq!(&msg.payload[..5], &[1, 0x55, 0x44, 0x33, 0x22]);
    let p = unsafe { msg.payload.as_ptr().add(5) };
    let data = msg.payload.slice(5..);
    assert_eq!(data.as_ptr(), p);
    assert!(data.iter().all(|b| *b == 17));
}
#[tokio::test]
async fn partial_header_and_payload_survive_cancellation() {
    use tokio::io::AsyncWriteExt;
    let (_, mut tx) = codecs(&[3; 32], true).unwrap();
    let encoded = tx
        .encode(DATA, 1, Protection::TlsPassthrough, b"body")
        .unwrap();
    for split in 1..encoded.len() {
        let (mut w, mut r) = tokio::io::duplex(128);
        let (mut rx, _) = codecs(&[3; 32], false).unwrap();
        w.write_all(&encoded[..split]).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), rx.read(&mut r))
                .await
                .is_err()
        );
        w.write_all(&encoded[split..]).await.unwrap();
        assert_eq!(rx.read(&mut r).await.unwrap().payload.as_ref(), b"body");
    }
    let (_, mut tx) = codecs(&[3; 32], true).unwrap();
    assert!(tx
        .encode(L5, 0, Protection::TlsPassthrough, b"control")
        .is_err());
}

#[tokio::test]
async fn raw_payload_has_no_tag_but_full_payload_is_authenticated() {
    for mode in [Protection::Full, Protection::TlsPassthrough] {
        let (_, mut tx) = codecs(&[7; 32], true).unwrap();
        let wire = tx.encode(DATA, 1, mode, b"payload").unwrap();
        assert_eq!(
            wire.len(),
            36 + 7 + if mode == Protection::Full { 16 } else { 0 }
        );
        let mut corrupted = wire.clone();
        corrupted[36] ^= 1;
        let (mut rx, _) = codecs(&[7; 32], false).unwrap();
        if mode == Protection::Full {
            assert!(rx.read(&mut &corrupted[..]).await.is_err());
        } else {
            assert!(rx.read(&mut &corrupted[..]).await.is_ok());
        }
        let (mut rx, _) = codecs(&[7; 32], false).unwrap();
        assert!(rx.read(&mut &wire[..wire.len() - 1]).await.is_err());
    }
}

#[test]
fn command_payload_limit_is_256_kib_not_io_buffer_capacity() {
    use l5_wire::MAX_PAYLOAD;
    assert_eq!(MAX_PAYLOAD, 256 * 1024);
    let (_, mut tx) = codecs(&[7; 32], true).unwrap();
    for mode in [Protection::Full, Protection::TlsPassthrough] {
        assert!(tx
            .prepare(DATA, 1, mode, Bytes::from(vec![0; MAX_PAYLOAD]))
            .is_ok());
        assert!(tx
            .prepare(DATA, 1, mode, Bytes::from(vec![0; MAX_PAYLOAD + 1]))
            .is_err());
    }
}
