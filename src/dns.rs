//! Minimal DNS codec used by virtual DNS and DNS-over-TCP/UDP rewrite.
//! Intentionally tiny: parse questions/answers, build A/AAAA responses, drop AAAA.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HEADER_LEN: usize = 12;
const MAX_HOPS: u8 = 16;
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;
const FLAG_QR: u16 = 0x8000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rrtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    pub fn to_vec(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());
        for q in &self.questions {
            out.extend_from_slice(&encode_name(&q.name)?);
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for rr in self.answers.iter().chain(&self.authorities).chain(&self.additionals) {
            encode_record(&mut out, rr)?;
        }
        Ok(out)
    }
}

fn encode_record(out: &mut Vec<u8>, rr: &Record) -> Result<(), String> {
    out.extend_from_slice(&encode_name(&rr.name)?);
    out.extend_from_slice(&rr.rrtype.to_be_bytes());
    out.extend_from_slice(&rr.class.to_be_bytes());
    out.extend_from_slice(&rr.ttl.to_be_bytes());
    out.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rr.rdata);
    Ok(())
}

fn encode_name(name: &str) -> Result<Vec<u8>, String> {
    let name = name.trim_end_matches('.');
    let mut out = Vec::new();
    if name.is_empty() {
        out.push(0);
        return Ok(out);
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("empty DNS label".into());
        }
        if label.len() > 63 {
            return Err("DNS label too long".into());
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

/// Read a domain name starting at `offset`. Returns (dot-form name with trailing '.', next offset).
fn read_name(msg: &[u8], offset: usize) -> Result<(String, usize), String> {
    fn rec(msg: &[u8], offset: usize, hops: u8) -> Result<(Vec<String>, usize), String> {
        if hops > MAX_HOPS {
            return Err("DNS name compression hop limit exceeded".into());
        }
        let mut pos = offset;
        let mut labels = Vec::new();
        loop {
            if pos >= msg.len() {
                return Err("truncated DNS name".into());
            }
            let len = msg[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                if pos + 1 >= msg.len() {
                    return Err("truncated DNS compression pointer".into());
                }
                let ptr = (((len as usize) & 0x3F) << 8) | (msg[pos + 1] as usize);
                if ptr >= msg.len() {
                    return Err("DNS compression pointer out of range".into());
                }
                let (suffix, _) = rec(msg, ptr, hops + 1)?;
                labels.extend(suffix);
                pos += 2;
                return Ok((labels, pos));
            }
            if len & 0xC0 != 0 {
                return Err("invalid DNS label".into());
            }
            let lab_len = len as usize;
            pos += 1;
            if pos + lab_len > msg.len() {
                return Err("truncated DNS label".into());
            }
            let label = std::str::from_utf8(&msg[pos..pos + lab_len]).map_err(|e| e.to_string())?;
            labels.push(label.to_string());
            pos += lab_len;
        }
        Ok((labels, pos))
    }

    let (labels, next) = rec(msg, offset, 0)?;
    let mut name = labels.join(".");
    name.push('.');
    Ok((name, next))
}

fn read_u16(msg: &[u8], pos: usize) -> Result<u16, String> {
    let bytes: [u8; 2] = msg.get(pos..pos + 2).ok_or("truncated DNS message")?.try_into().unwrap();
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(msg: &[u8], pos: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = msg.get(pos..pos + 4).ok_or("truncated DNS message")?.try_into().unwrap();
    Ok(u32::from_be_bytes(bytes))
}

fn read_rdata_with_names(msg: &[u8], rrtype: u16, start: usize, rdlen: usize) -> Result<Vec<u8>, String> {
    let end = start.checked_add(rdlen).ok_or("invalid rdlength")?;
    if end > msg.len() {
        return Err("truncated rdata".into());
    }
    // Expand compressed names inside well-known rdata so re-encoding is pointer-safe.
    match rrtype {
        TYPE_CNAME | TYPE_NS | TYPE_PTR => {
            let (name, consumed) = read_name(msg, start)?;
            if consumed > end {
                return Err("name overruns rdata".into());
            }
            encode_name(&name)
        }
        TYPE_MX => {
            if rdlen < 2 {
                return Err("truncated MX rdata".into());
            }
            let pref = &msg[start..start + 2];
            let (name, _) = read_name(msg, start + 2)?;
            let mut out = pref.to_vec();
            out.extend(encode_name(&name)?);
            Ok(out)
        }
        TYPE_SOA => {
            let (mname, pos) = read_name(msg, start)?;
            let (rname, pos) = read_name(msg, pos)?;
            if pos + 20 > end {
                return Err("truncated SOA rdata".into());
            }
            let mut out = encode_name(&mname)?;
            out.extend(encode_name(&rname)?);
            out.extend_from_slice(&msg[pos..pos + 20]);
            Ok(out)
        }
        TYPE_SRV => {
            if rdlen < 6 {
                return Err("truncated SRV rdata".into());
            }
            let head = &msg[start..start + 6];
            let (name, _) = read_name(msg, start + 6)?;
            let mut out = head.to_vec();
            out.extend(encode_name(&name)?);
            Ok(out)
        }
        _ => Ok(msg[start..end].to_vec()),
    }
}

fn read_record(msg: &[u8], mut pos: usize) -> Result<(Record, usize), String> {
    let (name, next) = read_name(msg, pos)?;
    pos = next;
    let rrtype = read_u16(msg, pos)?;
    pos += 2;
    let class = read_u16(msg, pos)?;
    pos += 2;
    let ttl = read_u32(msg, pos)?;
    pos += 4;
    let rdlen = read_u16(msg, pos)? as usize;
    pos += 2;
    let rdata = read_rdata_with_names(msg, rrtype, pos, rdlen)?;
    pos += rdlen;
    Ok((
        Record {
            name,
            rrtype,
            class,
            ttl,
            rdata,
        },
        pos,
    ))
}

fn parse_message(data: &[u8]) -> Result<Message, String> {
    if data.len() < HEADER_LEN {
        return Err("DNS message too short".into());
    }
    let id = read_u16(data, 0)?;
    let flags = read_u16(data, 2)?;
    let qdcount = read_u16(data, 4)? as usize;
    let ancount = read_u16(data, 6)? as usize;
    let nscount = read_u16(data, 8)? as usize;
    let arcount = read_u16(data, 10)? as usize;

    let mut pos = HEADER_LEN;
    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let (name, next) = read_name(data, pos)?;
        pos = next;
        let qtype = read_u16(data, pos)?;
        pos += 2;
        let qclass = read_u16(data, pos)?;
        pos += 2;
        questions.push(Question { name, qtype, qclass });
    }
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (rr, next) = read_record(data, pos)?;
        pos = next;
        answers.push(rr);
    }
    let mut authorities = Vec::with_capacity(nscount);
    for _ in 0..nscount {
        let (rr, next) = read_record(data, pos)?;
        pos = next;
        authorities.push(rr);
    }
    let mut additionals = Vec::with_capacity(arcount);
    for _ in 0..arcount {
        let (rr, next) = read_record(data, pos)?;
        pos = next;
        additionals.push(rr);
    }
    Ok(Message {
        id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
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
    parse_message(data)
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String, String> {
    let query = message.questions.first().ok_or("DnsRequest no query body")?;
    Ok(query.name.clone())
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    let rcode = message.flags & 0x000F;
    if rcode != 0 {
        return Err(format!("RCODE {rcode}"));
    }
    let mut cname = None;
    for answer in &message.answers {
        match answer.rrtype {
            TYPE_A if answer.rdata.len() == 4 => {
                let o = &answer.rdata;
                return Ok(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])));
            }
            TYPE_AAAA if answer.rdata.len() == 16 => {
                let o: [u8; 16] = answer.rdata.as_slice().try_into().unwrap();
                return Ok(IpAddr::V6(Ipv6Addr::from(o)));
            }
            TYPE_CNAME => {
                if let Ok((name, _)) = read_name(&answer.rdata, 0) {
                    cname = Some(name);
                }
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(cname);
    }
    Err(format!("{:?}", message.answers))
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers.retain(|answer| answer.rrtype != TYPE_AAAA);
}

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> Result<Message, String> {
    request.flags |= FLAG_QR;
    let (rrtype, rdata) = match ip {
        IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
        IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
    };
    request.answers.push(Record {
        name: if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{domain}.")
        },
        rrtype,
        class: CLASS_IN,
        ttl,
        rdata,
    });
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_query(id: u16, name: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        msg.extend_from_slice(&1u16.to_be_bytes()); // QD
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend(encode_name(name).unwrap());
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg
    }

    #[test]
    fn parse_minimal_a_query() {
        let data = a_query(0x1234, "example.com");
        let msg = parse_data_to_dns_message(&data, false).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert_eq!(extract_domain_from_dns_message(&msg).unwrap(), "example.com.");
        assert_eq!(msg.questions[0].qtype, TYPE_A);
    }

    #[test]
    fn build_a_response() {
        let data = a_query(0xABCD, "test.local");
        let req = parse_data_to_dns_message(&data, false).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let resp = build_dns_response(req, "test.local", ip, 5).unwrap();
        assert_ne!(resp.flags & FLAG_QR, 0);
        assert_eq!(resp.questions.len(), 1);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(extract_ipaddr_from_dns_message(&resp).unwrap(), ip);
        let bytes = resp.to_vec().unwrap();
        let reparsed = parse_data_to_dns_message(&bytes, false).unwrap();
        assert_eq!(reparsed.id, 0xABCD);
        assert_eq!(extract_ipaddr_from_dns_message(&reparsed).unwrap(), ip);
    }

    #[test]
    fn pointer_compression() {
        // Question name is a pointer to offset 12, where an uncompressed name lives
        // in a preceding... actually put the name at offset 12 as usual, then an
        // additional name that is a pointer back to 12.
        let mut data = a_query(0x0001, "example.com");
        // Append a dummy additional RR whose NAME is compression pointer 0xC00C
        // TYPE=CNAME CLASS=IN TTL=0 RDLENGTH=name
        data[10] = 0;
        data[11] = 1; // ARCOUNT = 1
        data.extend_from_slice(&[0xC0, 0x0C]); // pointer to QNAME at 12
        data.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        data.extend_from_slice(&CLASS_IN.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let rdata = encode_name("alias.example.com").unwrap();
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let msg = parse_data_to_dns_message(&data, false).unwrap();
        assert_eq!(msg.additionals.len(), 1);
        assert_eq!(msg.additionals[0].name, "example.com.");
        assert_eq!(extract_domain_from_dns_message(&msg).unwrap(), "example.com.");
    }

    #[test]
    fn tcp_length_prefix() {
        let inner = a_query(0x2222, "tcp.test");
        let mut wrapped = (inner.len() as u16).to_be_bytes().to_vec();
        wrapped.extend_from_slice(&inner);
        let msg = parse_data_to_dns_message(&wrapped, true).unwrap();
        assert_eq!(msg.id, 0x2222);
        assert_eq!(extract_domain_from_dns_message(&msg).unwrap(), "tcp.test.");
    }

    #[test]
    fn pointer_hop_limit() {
        // Self-referential pointer loop at offset 12
        let mut data = vec![0u8; HEADER_LEN + 2];
        data[4] = 0;
        data[5] = 1; // QDCOUNT=1
        data[12] = 0xC0;
        data[13] = 0x0C;
        assert!(parse_data_to_dns_message(&data, false).is_err());
    }
}
