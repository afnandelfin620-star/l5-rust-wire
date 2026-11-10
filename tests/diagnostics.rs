#![cfg(feature="size-diagnostics")]
use bytes::Bytes;
use std::{collections::VecDeque,task::{Context,Poll},io};
fn read(q:&mut VecDeque<Bytes>,_:&mut Context<'_>)->Poll<io::Result<Bytes>>{Poll::Ready(Ok(q.pop_front().unwrap_or_default()))}
#[tokio::test]
async fn count_complete_wire_messages_not_delivery_slices(){
 let(mut rx,_)=l5_wire::codecs(&[7;32],false).unwrap();let(_,mut tx)=l5_wire::codecs(&[7;32],true).unwrap();
 let mut wire=tx.encode(l5_wire::DATA,1,l5_wire::Protection::TlsPassthrough,&vec![8;65536]).unwrap();
 wire.extend(tx.encode(l5_wire::DATA,1,l5_wire::Protection::Full,b"full").unwrap());
 let mut q:VecDeque<_>=wire.chunks(1000).map(Bytes::copy_from_slice).collect();let mut got=0;let mut slices=0;
 while got<65536{let m=rx.read_owned(&mut q,read).await.unwrap();got+=m.payload.len();slices+=1;}
 assert!(slices>60);let s=l5_wire::diagnostics::snapshot();assert_eq!(s[1].0.iter().sum::<u64>(),1);assert_eq!(s[1].1.iter().sum::<u64>(),65536);
 assert_eq!(rx.read_owned(&mut q,read).await.unwrap().payload.as_ref(),b"full");let s=l5_wire::diagnostics::snapshot();assert_eq!(s[0].0.iter().sum::<u64>(),1);assert_eq!(s[0].1.iter().sum::<u64>(),4);
}
