#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};
use trust_dns_proto::op::MessageType;
use trust_dns_proto::{
    op::{Message, ResponseCode},
    rr::{record_type::RecordType, Name, RData, Record},
};

#[cfg(feature = "use-rand")]
pub fn build_dns_request(domain: &str, query_type: RecordType, used_by_tcp: bool) -> Result<Vec<u8>, String> {
    // [dependencies]
    // rand = "0.8"
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use trust_dns_proto::op::{header::MessageType, op_code::OpCode, query::Query};
    let name = Name::from_str(domain).map_err(|e| e.to_string())?;
    let query = Query::query(name, query_type);
    let mut msg = Message::new();
    msg.add_query(query)
        .set_id(StdRng::from_entropy().gen())
        .set_op_code(OpCode::Query)
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true);
    let mut msg_buf = msg.to_vec().map_err(|e| e.to_string())?;
    if used_by_tcp {
        let mut buf = (msg_buf.len() as u16).to_be_bytes().to_vec();
        buf.append(&mut msg_buf);
        Ok(buf)
    } else {
        Ok(msg_buf)
    }
}

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> Result<Message, String> {
    let record = match ip {
        IpAddr::V4(ip) => {
            let mut record = Record::with(Name::from_str(domain)?, RecordType::A, ttl);
            record.set_data(Some(RData::A(ip.into())));
            record
        }
        IpAddr::V6(ip) => {
            let mut record = Record::with(Name::from_str(domain)?, RecordType::AAAA, ttl);
            record.set_data(Some(RData::AAAA(ip.into())));
            record
        }
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request.set_message_type(MessageType::Response);

    request.add_answer(record);
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message
        .answers_mut()
        .retain(|answer| !matches!(answer.data(), Some(RData::AAAA(_))));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    if message.response_code() != ResponseCode::NoError {
        return Err(format!("{:?}", message.response_code()));
    }
    let mut cname = None;
    for answer in message.answers() {
        match answer.data().ok_or("DNS response not contains answer data")? {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(cname);
    }
    Err(format!("{:?}", message.answers()))
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String, String> {
    let query = message.queries().first().ok_or("DnsRequest no query body")?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("invalid dns data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("invalid dns data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}

// FIXME: use IpAddr::is_global() instead when it's stable
pub fn addr_is_private(addr: &SocketAddr) -> bool {
    fn is_benchmarking(addr: &Ipv4Addr) -> bool {
        addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
    }
    fn addr_v4_is_private(addr: &Ipv4Addr) -> bool {
        is_benchmarking(addr) || addr.is_private() || addr.is_loopback() || addr.is_link_local()
    }
    match addr {
        SocketAddr::V4(addr) => addr_v4_is_private(addr.ip()),
        SocketAddr::V6(_) => false,
    }
}
