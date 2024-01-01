#![allow(dead_code)]

use crate::error::Result;
use hashlink::{linked_hash_map::RawEntryMut, LruCache};
use smoltcp::wire::Ipv4Cidr;
use std::{
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::{Duration, Instant},
};

const MAPPING_TIMEOUT: u64 = 60; // Mapping timeout in seconds

struct NameCacheEntry {
    name: String,
    expiry: Instant,
}

pub struct VirtualDns {
    lru_cache: LruCache<IpAddr, NameCacheEntry>,
    name_to_ip: HashMap<String, IpAddr>,
    network_addr: IpAddr,
    broadcast_addr: IpAddr,
    next_addr: IpAddr,
}

impl Default for VirtualDns {
    fn default() -> Self {
        let start_addr = Ipv4Addr::from_str("198.18.0.0").unwrap();
        let cidr = Ipv4Cidr::new(start_addr.into(), 15);

        Self {
            next_addr: start_addr.into(),
            name_to_ip: HashMap::default(),
            network_addr: IpAddr::from(cidr.network().address().into_address()),
            broadcast_addr: IpAddr::from(cidr.broadcast().unwrap().into_address()),
            lru_cache: LruCache::new_unbounded(),
        }
    }
}

impl VirtualDns {
    pub fn new() -> Self {
        VirtualDns::default()
    }

    pub fn receive_query(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        use crate::dns;
        let message = dns::parse_data_to_dns_message(data, false)?;
        let qname = dns::extract_domain_from_dns_message(&message)?;
        let ip = self.allocate_ip(qname.clone())?;
        let message = dns::build_dns_response(message, &qname, ip, 5)?;
        Ok(message.to_vec()?)
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

    fn allocate_ip(&mut self, name: String) -> Result<IpAddr> {
        let now = Instant::now();

        loop {
            let (ip, entry) = match self.lru_cache.iter().next() {
                None => break,
                Some((ip, entry)) => (ip, entry),
            };
            if now > entry.expiry {
                let name = entry.name.clone();
                self.lru_cache.remove(&ip.clone());
                self.name_to_ip.remove(&name);
                continue;
            }
            break;
        }

        if let Some(ip) = self.name_to_ip.get(&name) {
            let ip = *ip;
            self.touch_ip(&ip);
            return Ok(ip);
        }

        let started_at = self.next_addr;

        loop {
            if let RawEntryMut::Vacant(vacant) = self.lru_cache.raw_entry_mut().from_key(&self.next_addr) {
                let expiry = Instant::now() + Duration::from_secs(MAPPING_TIMEOUT);
                let name0 = name.clone();
                vacant.insert(self.next_addr, NameCacheEntry { name, expiry });
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
