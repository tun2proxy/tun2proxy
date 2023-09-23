use mio::{event, windows::NamedPipe, Interest, Registry, Token};
use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use std::{
    fs::OpenOptions,
    io,
    net::{IpAddr, Ipv4Addr},
    os::windows::prelude::{FromRawHandle, IntoRawHandle, OpenOptionsExt},
    sync::Arc,
    vec::Vec,
};
use windows::{
    core::PCWSTR,
    Win32::{
        Security::Cryptography::{CryptAcquireContextW, CryptGenRandom, CryptReleaseContext, PROV_RSA_FULL},
        Storage::FileSystem::FILE_FLAG_OVERLAPPED,
    },
};

fn generate_random_bytes(len: usize) -> Result<Vec<u8>, windows::core::Error> {
    let mut buf = vec![0u8; len];
    unsafe {
        let mut h_prov = 0_usize;
        let null = PCWSTR::null();
        CryptAcquireContextW(&mut h_prov, null, null, PROV_RSA_FULL, 0)?;
        CryptGenRandom(h_prov, &mut buf)?;
        CryptReleaseContext(h_prov, 0)?;
    };
    Ok(buf)
}

fn server() -> io::Result<(NamedPipe, String)> {
    let num = generate_random_bytes(8).unwrap();
    let num = num.iter().fold(0, |acc, &x| acc * 256 + x as u64);
    let name = format!(r"\\.\pipe\my-pipe-{}", num);
    let pipe = NamedPipe::new(&name)?;
    Ok((pipe, name))
}

fn client(name: &str) -> io::Result<NamedPipe> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).custom_flags(FILE_FLAG_OVERLAPPED.0);
    let file = opts.open(name)?;
    unsafe { Ok(NamedPipe::from_raw_handle(file.into_raw_handle())) }
}

fn pipe() -> io::Result<(NamedPipe, NamedPipe)> {
    let (pipe, name) = server()?;
    Ok((pipe, client(&name)?))
}

/// A virtual TUN (IP) interface.
pub struct WinTunInterface {
    inner: Arc<wintun::Session>,
    mtu: usize,
    medium: Medium,
    pipe_server: NamedPipe,
    pipe_client: NamedPipe,
}

// impl AsRawFd for WinTunInterface {
//     fn as_raw_fd(&self) -> RawFd {
//         self.inner.borrow().as_raw_fd()
//     }
// }

impl event::Source for WinTunInterface {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        registry.register(&mut self.pipe_server, token, interests)?;
        Ok(())
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        registry.reregister(&mut self.pipe_server, token, interests)?;
        Ok(())
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        registry.deregister(&mut self.pipe_server)?;
        Ok(())
    }
}

impl WinTunInterface {
    pub fn new(name: &str, medium: Medium) -> io::Result<WinTunInterface> {
        let wintun = unsafe { wintun::load() }.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let tun_name = name;
        let adapter = match wintun::Adapter::open(&wintun, tun_name) {
            Ok(a) => a,
            Err(_) => wintun::Adapter::create(&wintun, tun_name, tun_name, None)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
        };

        let address = Ipv4Addr::new(10, 1, 0, 33);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let gateway = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)));
        adapter
            .set_network_addresses_tuple(IpAddr::V4(address), IpAddr::V4(mask), gateway)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let inner = Arc::new(session);

        let (pipe_server, pipe_client) = pipe()?;

        // let inner = WinTunInterfaceDesc::new(name, medium)?;
        // let mtu = inner.interface_mtu()?;
        let mtu = 1500;
        Ok(WinTunInterface {
            inner,
            mtu,
            medium,
            pipe_server,
            pipe_client,
        })
    }
}

impl Drop for WinTunInterface {
    fn drop(&mut self) {
        if let Err(e) = self.inner.shutdown() {
            log::error!("phy: failed to shutdown interface: {}", e);
        }
    }
}

impl Device for WinTunInterface {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut v = DeviceCapabilities::default();
        v.max_transmission_unit = self.mtu;
        v.medium = self.medium;
        v
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let inner = self.inner.clone();
        match inner.receive_blocking() {
            Ok(read_pack) => Some((
                RxToken {
                    buffer: read_pack.bytes().to_vec(),
                },
                TxToken { inner },
            )),
            Err(err) => {
                log::error!("phy: failed to receive packet: {}", err);
                None
            }
        }

        // match inner.recv(&mut buffer[..]) {
        //     Ok(size) => {
        //         buffer.resize(size, 0);
        //         let rx = RxToken { buffer };
        //         let tx = TxToken {
        //             inner: self.inner.clone(),
        //         };
        //         Some((rx, tx))
        //     }
        //     Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
        //     Err(err) => panic!("{}", err),
        // }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            inner: self.inner.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    inner: Arc<wintun::Session>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let inner = self.inner.clone();
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);

        let write_pack = inner.allocate_send_packet(len as u16);
        if let Ok(mut write_pack) = write_pack {
            write_pack.bytes_mut().copy_from_slice(&buffer[..]);
            inner.send_packet(write_pack);
        } else if let Err(err) = write_pack {
            log::error!("phy: failed to allocate send packet: {}", err);
        }

        // match lower.send(&buffer[..]) {
        //     Ok(_) => {}
        //     Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
        //         log::error!("phy: tx failed due to WouldBlock")
        //     }
        //     Err(err) => panic!("{}", err),
        // }
        result
    }
}
