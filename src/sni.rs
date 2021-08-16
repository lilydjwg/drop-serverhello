use pnet_packet::tcp::TcpPacket;
use pnet_packet::Packet;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};

pub struct Verdictor { }

impl Verdictor {
  pub fn new() -> Self {
    Self { }
  }

  pub fn check_packet(&mut self, data: &[u8]) -> Option<()> {
    let tcp = if data[0] == 4 {
      TcpPacket::new(&data[20..])?
    } else {
      TcpPacket::new(&data[40..])?
    };

    let payload = tcp.payload();
    if let Ok((_rem, r)) = parse_tls_plaintext(payload) {
      if let TlsMessage::Handshake(handshake) = &r.msg[0] {
        if let TlsMessageHandshake::ServerHello(_) = handshake {
          eprint!(".");
          return Some(());
        }
      }
    }

    None
  }
}
