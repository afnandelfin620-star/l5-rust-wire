
use std::{pin::Pin,task::{Context,Poll},time::Duration,future::Future};
use tokio::io::{AsyncRead,AsyncWrite,ReadBuf};
use futures::SinkExt;
use bytes::Bytes;
use l5_wire::transport::{Message,Transport};
struct Slow { delay:Pin<Box<tokio::time::Sleep>>, interval:Duration }
impl AsyncRead for Slow {fn poll_read(self:Pin<&mut Self>,_:&mut Context<'_>,_:&mut ReadBuf<'_>)->Poll<std::io::Result<()>> {Poll::Pending}}
impl AsyncWrite for Slow {
 fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,b:&[u8])->Poll<std::io::Result<usize>>{
  if self.delay.as_mut().poll(cx).is_pending(){return Poll::Pending;}
  let interval=self.interval;self.delay.as_mut().reset(tokio::time::Instant::now()+interval);
  Poll::Ready(Ok(b.len().min(1)))
 }
 fn poll_flush(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<std::io::Result<()>> {Poll::Ready(Ok(()))}
 fn poll_shutdown(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<std::io::Result<()>> {Poll::Ready(Ok(()))}
}
#[tokio::test(start_paused=true)]
async fn slow_continuous_progress_outlives_total_timeout_but_stall_fails(){
 for (seconds, success) in [(4,true),(11,false)] {
  let interval=Duration::from_secs(seconds);
  let io=Slow{delay:Box::pin(tokio::time::sleep(interval)),interval};
  let mut t=Transport::new(io,&[9;32],true).unwrap();t.set_write_timeout(Duration::from_secs(10));
  let start=tokio::time::Instant::now();
  let result=t.send(Message::Data{id:1,payload:Bytes::from_static(b"abc")}).await;
  assert_eq!(result.is_ok(),success);
  if success {assert!(start.elapsed()>Duration::from_secs(10));}
  else {assert_eq!(start.elapsed(),Duration::from_secs(10));}
 }
}
