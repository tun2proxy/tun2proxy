use smoltcp::{phy::Medium, wire::EthernetFrame};
use std::{
    io,
    os::unix::io::{AsRawFd, RawFd},
};

#[derive(Debug)]
pub struct TunTapInterfaceDesc {
    lower: libc::c_int,
    mtu: usize,
}

impl AsRawFd for TunTapInterfaceDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl TunTapInterfaceDesc {
    pub fn new(name: &str, medium: Medium) -> io::Result<TunTapInterfaceDesc> {
        let lower = unsafe {
            let lower = libc::open(
                "/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK,
            );
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        let mut ifreq = ifreq_for(name);
        Self::attach_interface_ifreq(lower, medium, &mut ifreq)?;
        let mtu = Self::mtu_ifreq(medium, &mut ifreq)?;

        Ok(TunTapInterfaceDesc { lower, mtu })
    }

    pub fn from_fd(fd: RawFd, mtu: usize) -> io::Result<TunTapInterfaceDesc> {
        Ok(TunTapInterfaceDesc { lower: fd, mtu })
    }

    fn attach_interface_ifreq(lower: libc::c_int, medium: Medium, ifr: &mut Ifreq) -> io::Result<()> {
        let mode = match medium {
            Medium::Ip => imp::IFF_TUN,
            Medium::Ethernet => imp::IFF_TAP,
            Medium::Ieee802154 => todo!(),
        };
        ifr.ifr_data = mode | imp::IFF_NO_PI;
        ifreq_ioctl(lower, ifr, imp::TUNSETIFF).map(|_| ())
    }

    fn mtu_ifreq(medium: Medium, ifr: &mut Ifreq) -> io::Result<usize> {
        let lower = unsafe {
            let lower = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP);
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        let ip_mtu = ifreq_ioctl(lower, ifr, imp::SIOCGIFMTU).map(|mtu| mtu as usize);

        unsafe {
            libc::close(lower);
        }

        // Propagate error after close, to ensure we always close.
        let ip_mtu = ip_mtu?;

        // SIOCGIFMTU returns the IP MTU (typically 1500 bytes.)
        // smoltcp counts the entire Ethernet packet in the MTU, so add the Ethernet header size to it.
        let mtu = match medium {
            Medium::Ip => ip_mtu,
            Medium::Ethernet => ip_mtu + EthernetFrame::<&[u8]>::header_len(),
            Medium::Ieee802154 => todo!(),
        };

        Ok(mtu)
    }

    pub fn interface_mtu(&self) -> io::Result<usize> {
        Ok(self.mtu)
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::read(self.lower, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len());
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::write(self.lower, buffer.as_ptr() as *const libc::c_void, buffer.len());
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }
}

impl Drop for TunTapInterfaceDesc {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.lower);
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct Ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int, /* ifr_ifindex or ifr_mtu */
}

fn ifreq_for(name: &str) -> Ifreq {
    let mut ifreq = Ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_data: 0,
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char
    }
    ifreq
}

fn ifreq_ioctl(lower: libc::c_int, ifreq: &mut Ifreq, cmd: libc::c_ulong) -> io::Result<libc::c_int> {
    unsafe {
        let res = libc::ioctl(lower, cmd as _, ifreq as *mut Ifreq);
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(ifreq.ifr_data)
}

mod imp {
    pub const SIOCGIFMTU: libc::c_ulong = 0x8921;
    // pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;
    // pub const ETH_P_ALL: libc::c_short = 0x0003;
    // pub const ETH_P_IEEE802154: libc::c_short = 0x00F6;

    pub const TUNSETIFF: libc::c_ulong = 0x400454CA;
    pub const IFF_TUN: libc::c_int = 0x0001;
    pub const IFF_TAP: libc::c_int = 0x0002;
    pub const IFF_NO_PI: libc::c_int = 0x1000;
}
