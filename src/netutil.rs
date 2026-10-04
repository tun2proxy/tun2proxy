use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// TUN address assigned by tproxy-config 7.0.7 (`10.0.0.33`).
pub const TUN_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
/// TUN netmask assigned by tproxy-config 7.0.7 (`255.255.255.0`).
pub const TUN_NETMASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
/// TUN gateway assigned by tproxy-config 7.0.7 (`10.0.0.1`).
pub const TUN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

/// IPv4 or IPv6 network in CIDR notation (`addr` + prefix length).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpCidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, String> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("prefix {prefix} exceeds {max} for {addr}"));
        }
        Ok(Self { addr, prefix })
    }

    pub fn first_address(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from_bits(u32::from(ip) & ipv4_mask(self.prefix))),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from_bits(u128::from(ip) & ipv6_mask(self.prefix))),
        }
    }

    pub fn last_address(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from_bits(u32::from(ip) | !ipv4_mask(self.prefix))),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from_bits(u128::from(ip) | !ipv6_mask(self.prefix))),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(other)) => {
                let first = match self.first_address() {
                    IpAddr::V4(v) => u32::from(v),
                    _ => unreachable!(),
                };
                let last = match self.last_address() {
                    IpAddr::V4(v) => u32::from(v),
                    _ => unreachable!(),
                };
                let n = u32::from(other);
                n >= first && n <= last
            }
            (IpAddr::V6(_), IpAddr::V6(other)) => {
                let first = match self.first_address() {
                    IpAddr::V6(v) => u128::from(v),
                    _ => unreachable!(),
                };
                let last = match self.last_address() {
                    IpAddr::V6(v) => u128::from(v),
                    _ => unreachable!(),
                };
                let n = u128::from(other);
                n >= first && n <= last
            }
            _ => false,
        }
    }
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for IpCidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((addr, prefix)) = s.split_once('/') {
            let addr: IpAddr = addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?;
            let prefix: u8 = prefix.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
            Self::new(addr, prefix)
        } else {
            let addr: IpAddr = s.parse().map_err(|e: std::net::AddrParseError| e.to_string())?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Self::new(addr, prefix)
        }
    }
}

impl serde::Serialize for IpCidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for IpCidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// RFC 5735/6890 private-like addresses, plus the 198.18.0.0/15 benchmarking
/// range used as the default virtual-DNS pool so Fake-IP rewrite still matches.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => ipv4_is_private_like(addr),
        IpAddr::V6(addr) => {
            if addr.is_loopback() || addr.is_unspecified() || addr.is_unique_local() || addr.is_unicast_link_local() {
                return true;
            }
            if let Some(v4) = addr.to_ipv4_mapped() {
                return ipv4_is_private_like(v4);
            }
            false
        }
    }
}

fn ipv4_is_private_like(addr: Ipv4Addr) -> bool {
    addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_unspecified()
        || is_benchmarking(addr)
}

/// 198.18.0.0/15 — RFC 2544 benchmarking / virtual DNS default pool.
fn is_benchmarking(addr: Ipv4Addr) -> bool {
    addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
}

#[cfg(feature = "setup")]
impl IpCidr {
    /// Convert to `tproxy-config`'s `cidr::IpCidr` (network address + prefix).
    pub fn to_tproxy_cidr(self) -> Result<tproxy_config::IpCidr, String> {
        let s = format!("{}/{}", self.first_address(), self.prefix);
        s.parse::<tproxy_config::IpCidr>().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_and_host() {
        let c: IpCidr = "198.18.0.0/15".parse().unwrap();
        assert_eq!(c.first_address(), "198.18.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(c.last_address(), "198.19.255.255".parse::<IpAddr>().unwrap());
        assert!(c.contains("198.18.0.1".parse().unwrap()));
        assert!(!c.contains("10.0.0.1".parse().unwrap()));

        let h: IpCidr = "8.8.8.8".parse().unwrap();
        assert_eq!(h.prefix, 32);
        assert_eq!(h.first_address(), h.last_address());
    }

    #[test]
    fn private_like_ips() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));
        assert!(is_private_ip("198.18.0.1".parse().unwrap()));
        assert!(is_private_ip("::1".parse().unwrap()));
        assert!(is_private_ip("fc00::1".parse().unwrap()));
        assert!(is_private_ip("fe80::1".parse().unwrap()));
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
    }
}
