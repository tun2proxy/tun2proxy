use crate::error::Result;
use hashlink::{LruCache, linked_hash_map::RawEntryMut};
use hickory_proto::{op::MessageType, rr::RecordType};
use std::{
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
use tproxy_config::IpCidr;

const MAPPING_TIMEOUT: u64 = 60; // Mapping timeout in seconds

struct NameCacheEntry {
    name: String,
    expiry: Instant,
}

/// A virtual DNS server which allocates IP addresses to clients.
/// The IP addresses are in the range of private IP addresses.
/// The DNS server is implemented as a LRU cache.
pub struct VirtualDns {
    trailing_dot: bool,
    lru_cache: LruCache<IpAddr, NameCacheEntry>,
    name_to_ip: HashMap<String, IpAddr>,
    network_addr: IpAddr,
    broadcast_addr: IpAddr,
    next_addr: IpAddr,
}

impl VirtualDns {
    pub fn new(ip_pool: IpCidr) -> Self {
        Self {
            trailing_dot: false,
            next_addr: ip_pool.first_address(),
            name_to_ip: HashMap::default(),
            network_addr: ip_pool.first_address(),
            broadcast_addr: ip_pool.last_address(),
            lru_cache: LruCache::new_unbounded(),
        }
    }

    /// Returns the DNS response to send back to the client.
    pub fn generate_query(&mut self, data: &[u8]) -> Result<(Vec<u8>, String, IpAddr)> {
        use crate::dns;
        let mut message = dns::parse_data_to_dns_message(data, false)?;
        let qname = dns::extract_domain_from_dns_message(&message)?;
        let query_type = message.queries[0].query_type();
        let ip = self.find_or_allocate_ip(qname.clone())?;
        if matches!((query_type, ip.is_ipv4()), (RecordType::A, true) | (RecordType::AAAA, false)) {
            message = dns::build_dns_response(message, &qname, ip, 5)?;
        } else {
            message.metadata.message_type = MessageType::Response;
        }
        Ok((message.to_vec()?, qname, ip))
    }

    fn increment_ip(addr: IpAddr) -> Result<IpAddr> {
        let mut ip_bytes = match addr as IpAddr {
            IpAddr::V4(ip) => Vec::<u8>::from(ip.octets()),
            IpAddr::V6(ip) => Vec::<u8>::from(ip.octets()),
        };

        // Traverse bytes from right to left and stop when we can add one.
        for j in 0..ip_bytes.len() {
            let i = ip_bytes.len() - 1 - j;
            if ip_bytes[i] != 255 {
                // We can add 1 without carry and are done.
                ip_bytes[i] += 1;
                break;
            } else {
                // Zero this byte and carry over to the next one.
                ip_bytes[i] = 0;
            }
        }

        let addr = if addr.is_ipv4() {
            let bytes: [u8; 4] = ip_bytes.as_slice().try_into()?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        } else {
            let bytes: [u8; 16] = ip_bytes.as_slice().try_into()?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        };
        Ok(addr)
    }

    // This is to be called whenever we receive or send a packet on the socket
    // which connects the tun interface to the client, so existing IP address to name
    // mappings to not expire as long as the connection is active.
    pub fn touch_ip(&mut self, addr: &IpAddr) {
        _ = self.lru_cache.get_mut(addr).map(|entry| {
            entry.expiry = Instant::now() + Duration::from_secs(MAPPING_TIMEOUT);
        });
    }

    pub fn resolve_ip(&mut self, addr: &IpAddr) -> Option<&String> {
        self.lru_cache.get(addr).map(|entry| &entry.name)
    }

    fn find_or_allocate_ip(&mut self, name: String) -> Result<IpAddr> {
        // This function is a search and creation function.
        // Thus, it is sufficient to canonicalize the name here.
        let insert_name = if name.ends_with('.') && !self.trailing_dot {
            String::from(name.trim_end_matches('.'))
        } else {
            name
        };

        let now = Instant::now();

        // Iterate through all entries of the LRU cache and remove those that have expired.
        loop {
            let (ip, entry) = match self.lru_cache.iter().next() {
                None => break,
                Some((ip, entry)) => (ip, entry),
            };

            // The entry has expired.
            if now > entry.expiry {
                let name = entry.name.clone();
                self.lru_cache.remove(&ip.clone());
                self.name_to_ip.remove(&name);
                continue; // There might be another expired entry after this one.
            }

            break; // The entry has not expired and all following entries are newer.
        }

        // Return the IP if it is stored inside our LRU cache.
        if let Some(ip) = self.name_to_ip.get(&insert_name) {
            let ip = *ip;
            self.touch_ip(&ip);
            return Ok(ip);
        }

        // Otherwise, store name and IP pair inside the LRU cache.
        let started_at = self.next_addr;

        loop {
            if let RawEntryMut::Vacant(vacant) = self.lru_cache.raw_entry_mut().from_key(&self.next_addr) {
                let expiry = Instant::now() + Duration::from_secs(MAPPING_TIMEOUT);
                let name0 = insert_name.clone();
                vacant.insert(self.next_addr, NameCacheEntry { name: insert_name, expiry });
                self.name_to_ip.insert(name0, self.next_addr);
                return Ok(self.next_addr);
            }
            self.next_addr = Self::increment_ip(self.next_addr)?;
            if self.next_addr == self.broadcast_addr {
                // Wrap around.
                self.next_addr = self.network_addr;
            }
            if self.next_addr == started_at {
                return Err("Virtual IP space for DNS exhausted".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{Message, OpCode, Query},
        rr::{Name, RecordType},
    };
    use std::str::FromStr;

    fn query_wire(name: &str, query_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(0, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_str(name).unwrap(), query_type));
        message.to_vec().unwrap()
    }

    fn dns(pool: &str) -> VirtualDns {
        VirtualDns::new(IpCidr::from_str(pool).unwrap())
    }

    #[test]
    fn virtual_dns_answers_only_the_address_family_of_its_pool() {
        let mut ipv4_dns = dns("198.18.0.0/15");
        let (a_response, _, ipv4) = ipv4_dns.generate_query(&query_wire("example.org.", RecordType::A)).unwrap();
        assert!(ipv4.is_ipv4());
        let a_response = Message::from_vec(&a_response).unwrap();
        assert_eq!(a_response.answers.len(), 1);
        assert!(matches!(a_response.answers[0].data, hickory_proto::rr::RData::A(_)));

        let (aaaa_response, _, _) = ipv4_dns.generate_query(&query_wire("example.org.", RecordType::AAAA)).unwrap();
        let aaaa_response = Message::from_vec(&aaaa_response).unwrap();
        assert_eq!(aaaa_response.metadata.message_type, MessageType::Response);
        assert!(aaaa_response.answers.is_empty());

        let mut ipv6_dns = dns("2001:db8::/120");
        let (aaaa_response, _, ipv6) = ipv6_dns.generate_query(&query_wire("example.org.", RecordType::AAAA)).unwrap();
        assert!(ipv6.is_ipv6());
        let aaaa_response = Message::from_vec(&aaaa_response).unwrap();
        assert_eq!(aaaa_response.answers.len(), 1);
        assert!(matches!(aaaa_response.answers[0].data, hickory_proto::rr::RData::AAAA(_)));

        let (a_response, _, _) = ipv6_dns.generate_query(&query_wire("example.org.", RecordType::A)).unwrap();
        let a_response = Message::from_vec(&a_response).unwrap();
        assert!(a_response.answers.is_empty());
    }

    #[test]
    fn expired_mapping_is_reclaimed_and_active_mapping_can_be_touched() {
        let mut dns = dns("198.18.0.0/29");
        let name = "expired.example".to_string();
        let ip = dns.find_or_allocate_ip(name.clone()).unwrap();
        dns.lru_cache.get_mut(&ip).unwrap().expiry = Instant::now() - Duration::from_secs(1);

        let reclaimed_ip = dns.find_or_allocate_ip(name.clone()).unwrap();
        assert_eq!(reclaimed_ip, ip);

        dns.lru_cache.get_mut(&ip).unwrap().expiry = Instant::now() - Duration::from_secs(1);
        dns.touch_ip(&ip);
        let touched_ip = dns.find_or_allocate_ip(name).unwrap();
        assert_eq!(touched_ip, ip);
    }
}
