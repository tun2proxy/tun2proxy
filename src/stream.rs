use std::collections::VecDeque;
use std::io::{Read, Write};
use mio::net::TcpStream;
use crate::error::Error;

struct Stream {
    write_buf: VecDeque<u8>,
}

impl Stream {
    pub fn writable_bytes(&self) -> usize {
        return self.write_buf.len();
    }

    pub fn read_data(&mut self, data: &[u8]) {

    }

    pub fn forward(&mut self, tcp_stream: &mut TcpStream) {
        //tcp_stream.write()
    }

    /*pub fn read(&mut self, tcp_socket: &mut smoltcp::socket::Socket::Tcp) {
        //tcp_socket.read()
    }*/
}

struct DnsProxy {
    query: Vec<u8>,
    response: Option<Vec<u8>>,
}

impl DnsProxy {
    pub fn receive_query(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() > 0xffff {
            return Err("DNS payload too large".into());
        }
        Ok(Self {
            query: Vec::from(payload),
            response: None,
        })
    }

    pub fn get_response(&self) -> Result<Option<&[u8]>, Error> {
        Ok(match &self.response {
            None => None,
            Some(bytes) => Some(bytes.as_slice())
        })
    }
}