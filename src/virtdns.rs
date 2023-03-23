use smoltcp::wire::{IpCidr, Ipv4Cidr};
use std::collections::{HashMap, LinkedList};
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code, clippy::upper_case_acronyms)]
enum DnsRecordType {
    A = 1,
    AAAA = 28,
}

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum DnsClass {
    IN = 1,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct VirtualDns {
    mapping: HashMap<IpAddr, String>,
    expiry: LinkedList<IpAddr>,
    cidr: IpCidr,
    next_addr: IpAddr,
}

impl Default for VirtualDns {
    fn default() -> Self {
        let start_addr = Ipv4Addr::from_str("198.18.0.0").unwrap();
        Self {
            cidr: Ipv4Cidr::new(start_addr.into(), 15).into(),
            next_addr: start_addr.into(),
            mapping: Default::default(),
            expiry: Default::default(),
        }
    }
}

impl VirtualDns {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn receive_query(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 17 {
            return None;
        }
        // bit 1: Message is a query (0)
        // bits 2 - 5: Standard query opcode (0)
        // bit 6: Unused
        // bit 7: Message is not truncated (0)
        // bit 8: Recursion desired (1)
        let is_supported_query = (data[2] & 0b11111011) == 0b00000001;
        let num_queries = (data[4] as u16) << 8 | data[5] as u16;
        if !is_supported_query || num_queries != 1 {
            return None;
        }

        let result = VirtualDns::parse_qname(data, 12);
        result.as_ref()?;
        let (qname, offset) = result.unwrap();
        if offset + 3 >= data.len() {
            return None;
        }
        let qtype = (data[offset] as u16) << 8 | data[offset + 1] as u16;
        let qclass = (data[offset + 2] as u16) << 8 | data[offset + 3] as u16;

        if qtype != DnsRecordType::A as u16 && qtype != DnsRecordType::AAAA as u16
            || qclass != DnsClass::IN as u16
        {
            return None;
        }

        log::info!("DNS query: {}", qname);

        let mut response = Vec::<u8>::new();
        response.extend(&data[0..offset + 4]);
        response[2] |= 0x80; // Message is a response
        response[3] |= 0x80; // Recursion available
        response[6] = 0;
        response[7] = if qtype == DnsRecordType::A as u16 {
            1
        } else {
            0
        }; // one answer record

        // zero other sections
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;

        if let Some(ip) = self.name_to_ip(qname) {
            if qtype == DnsRecordType::A as u16 {
                response.extend(&[
                    0xc0, 0x0c, // Question name pointer
                    0, 1, // Record type: A
                    0, 1, // Class: IN
                    0, 0, 0, 1, // TTL: 30 seconds
                    0, 4, // Data length: 4 bytes
                ]);
                match ip as IpAddr {
                    IpAddr::V4(ip) => response.extend(ip.octets().as_ref()),
                    IpAddr::V6(ip) => response.extend(ip.octets().as_ref()),
                };
            }
        } else {
            log::error!("Virtual IP space for DNS exhausted");
            response[7] = 0; // No answers
        }
        Some(response)
    }

    fn increment_ip(addr: IpAddr) -> IpAddr {
        let mut ip_bytes = match addr as IpAddr {
            IpAddr::V4(ip) => Vec::<u8>::from(ip.octets()),
            IpAddr::V6(ip) => Vec::<u8>::from(ip.octets()),
        };
        for j in 0..ip_bytes.len() {
            let i = ip_bytes.len() - 1 - j;
            if ip_bytes[i] != 255 {
                ip_bytes[i] += 1;
                break;
            } else {
                ip_bytes[i] = 0;
            }
        }
        if addr.is_ipv4() {
            let bytes: [u8; 4] = ip_bytes.as_slice().try_into().unwrap();
            IpAddr::V4(Ipv4Addr::from(bytes))
        } else {
            let bytes: [u8; 16] = ip_bytes.as_slice().try_into().unwrap();
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
    }

    pub fn ip_to_name(&self, addr: &IpAddr) -> Option<&String> {
        self.mapping.get(addr)
    }

    fn name_to_ip(&mut self, name: String) -> Option<IpAddr> {
        self.next_addr = Self::increment_ip(self.next_addr);
        self.mapping.insert(self.next_addr, name);
        // TODO: Check if next_addr is CIDR broadcast address and overflow.
        // TODO: Caching.
        Some(self.next_addr)
    }

    fn parse_qname(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
        let label_type = data[offset] & 0xC0;
        if label_type != 0x00 {
            return None;
        }
        let mut qname = String::from("");
        loop {
            if offset >= data.len() {
                return None;
            }
            let label_len = data[offset];
            if label_len == 0 {
                offset += 1;
                break;
            }
            for _ in 0..label_len {
                offset += 1;
                if offset >= data.len() {
                    return None;
                }
                qname.push(data[offset] as char);
            }
            qname.push('.');
            offset += 1;
        }

        Some((qname, offset))
    }
}
