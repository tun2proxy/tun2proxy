use crate::error::Error;
use smoltcp::wire::IpCidr;
use std::net::IpAddr;
use std::str::FromStr;

pub fn str_to_cidr(s: &str) -> Result<IpCidr, Error> {
    // IpCidr's FromString implementation requires the netmask to be specified.
    // Try to parse as IP address without netmask before falling back.
    match IpAddr::from_str(s) {
        Err(_) => (),
        Ok(cidr) => {
            let prefix_len = if cidr.is_ipv4() { 32 } else { 128 };
            return Ok(IpCidr::new(cidr.into(), prefix_len));
        }
    };

    let cidr = IpCidr::from_str(s);
    match cidr {
        Err(()) => Err("Invalid CIDR: ".into()),
        Ok(cidr) => Ok(cidr),
    }
}
