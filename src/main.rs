extern crate netfilter_queue as nfq;

use std::ptr::null;

use failure::Error;
use log::{debug, info};
use nfq::error::Error as NfqError;
use nfq::handle::{Handle, ProtocolFamily};
use nfq::message::{Message, Payload};
use nfq::queue::{CopyMode, PacketHandler, QueueHandle, Verdict};

mod sni;

fn main() -> Result<(), Error> {
  env_logger::init();

  let v = sni::Verdictor::new();

  let mut handle = Handle::new()?;
  handle.bind(ProtocolFamily::INET)?;

  let mut queue = handle.queue(9, v)?;
  queue.set_mode(CopyMode::Packet(PACKET_SIZE))?;

  info!("Listening for packets...");

  handle.start(PACKET_SIZE)?;
  Ok(())
}

const PACKET_SIZE: u16 = 4096;

impl PacketHandler for sni::Verdictor {
  fn handle(&mut self, hq: QueueHandle, message: Result<&Message, &NfqError>) -> i32 {
    let message = if let Ok(m) = message { m } else { return 0 };

    let h = unsafe { message.ip_header() }.unwrap();
    debug!("Packet received: {:?} -> {:?}", h.saddr(), h.daddr());
    let (payload, len) = unsafe { message.payload::<Packet>() }.unwrap();

    let _ = if let Some(_) = self.check_packet(&payload.data[..len]) {
      Verdict::set_verdict(
        hq,
        message.header.id(),
        Verdict::Drop,
        0,
        null(),
      )
    } else {
      Verdict::set_verdict(hq, message.header.id(), Verdict::Accept, 0, null())
    };

    0
  }
}

#[repr(C, packed)]
struct Packet {
  data: [u8; PACKET_SIZE as usize],
}

impl Payload for Packet {}
