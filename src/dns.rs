use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{
        Name, RData, Record,
        rdata::{A, AAAA},
    },
};
use std::io::{Error, ErrorKind::InvalidData, ErrorKind::UnexpectedEof};
use std::{net::IpAddr, str::FromStr};

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> std::io::Result<Message> {
    let name = Name::from_str(domain).map_err(|e| Error::new(InvalidData, e))?;
    let record = match ip {
        IpAddr::V4(ip) => Record::from_rdata(name.clone(), ttl, RData::A(A(ip))),
        IpAddr::V6(ip) => Record::from_rdata(name, ttl, RData::AAAA(AAAA(ip))),
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request.metadata.message_type = MessageType::Response;

    request.add_answer(record);
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers.retain(|answer| !matches!(&answer.data, RData::AAAA(_)));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> std::io::Result<IpAddr> {
    if message.metadata.response_code != ResponseCode::NoError {
        return Err(Error::new(InvalidData, format!("{:?}", message.metadata.response_code)));
    }
    let mut cname = None;
    for answer in &message.answers {
        match &answer.data {
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
        return Err(Error::new(InvalidData, cname));
    }
    Err(Error::new(InvalidData, format!("{:?}", message.answers)))
}

pub fn extract_domain_from_dns_message(message: &Message) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind::InvalidData};
    let query = message.queries.first().ok_or(Error::new(InvalidData, "DnsRequest no query body"))?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> std::io::Result<Message> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err(Error::new(UnexpectedEof, "invalid dns data"));
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or(Error::new(UnexpectedEof, "invalid dns data"))?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| Error::new(InvalidData, e))?;
    Ok(message)
}
