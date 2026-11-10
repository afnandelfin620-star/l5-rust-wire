
use std::{pin::Pin,sync::{Arc,Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}},task::{Context,Poll,Waker}};
use tokio::io::{AsyncRead,AsyncWrite,ReadBuf};
use futures::{Sink,Stream,StreamExt,task::{ArcWake,waker}};
use bytes::Bytes;
use l5_wire::{transport::{Message,Transport},codecs,Protection,PING};
struct Wake(AtomicUsize);
impl ArcWake for Wake {fn wake_by_ref(s:&Arc<Self>){s.0.fetch_add(1,Ordering::SeqCst);}}
struct Shared {blocked:AtomicBool,last:Mutex<Option<Waker>>}
struct Io {shared:Arc<Shared>,input:Bytes}
impl AsyncRead for Io {
 fn poll_read(mut self:Pin<&mut Self>,_:&mut Context<'_>,b:&mut ReadBuf<'_>)->Poll<std::io::Result<()>> {
  if self.input.is_empty(){return Poll::Pending;}
  let n=b.remaining().min(self.input.len());b.put_slice(&self.input.split_to(n));Poll::Ready(Ok(()))
 }
}
impl AsyncWrite for Io {
 fn poll_write(self:Pin<&mut Self>,cx:&mut Context<'_>,b:&[u8])->Poll<std::io::Result<usize>>{
  if self.shared.blocked.load(Ordering::SeqCst){*self.shared.last.lock().unwrap()=Some(cx.waker().clone());Poll::Pending}else{Poll::Ready(Ok(b.len()))}
 }
 fn poll_flush(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<std::io::Result<()>>{Poll::Ready(Ok(()))}
 fn poll_shutdown(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<std::io::Result<()>>{Poll::Ready(Ok(()))}
}
#[test]
fn reader_does_not_steal_single_write_waker(){
 let (_,mut peer)=codecs(&[9;32],false).unwrap();
 let ping=peer.encode(PING,0,Protection::Full,b"ping").unwrap();
 let shared=Arc::new(Shared{blocked:AtomicBool::new(true),last:Mutex::new(None)});
 let io=Io{shared:shared.clone(),input:ping.into()};
 let t=Transport::new(io,&[9;32],true).unwrap();let(mut tx,mut rx)=t.split();
 let w=Arc::new(Wake(AtomicUsize::new(0)));let r=Arc::new(Wake(AtomicUsize::new(0)));
 let ww=waker(w.clone());let rw=waker(r.clone());let mut wc=Context::from_waker(&ww);let mut rc=Context::from_waker(&rw);
 assert!(Pin::new(&mut tx).poll_ready(&mut wc).is_ready());
 Pin::new(&mut tx).start_send(Message::Data{id:1,payload:Bytes::from_static(b"upload")}).unwrap();
 assert!(Pin::new(&mut tx).poll_flush(&mut wc).is_pending());
 assert!(matches!(Pin::new(&mut rx).poll_next(&mut rc),Poll::Ready(Some(Ok(Message::Ping(_))))));
 assert!(Pin::new(&mut rx).poll_next(&mut rc).is_pending());
 w.0.store(0,Ordering::SeqCst);r.0.store(0,Ordering::SeqCst);
 shared.blocked.store(false,Ordering::SeqCst);shared.last.lock().unwrap().take().unwrap().wake();
 assert_eq!(w.0.load(Ordering::SeqCst),1);assert_eq!(r.0.load(Ordering::SeqCst),0);
 assert!(Pin::new(&mut rx).poll_next(&mut rc).is_pending());
 assert_eq!(w.0.load(Ordering::SeqCst),1,"writer remains the sole write readiness owner");
 // Poll the correctly woken writer; it drains both data and queued Pong.
 assert!(Pin::new(&mut tx).poll_flush(&mut wc).is_ready());
}
