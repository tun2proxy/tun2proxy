use mio::{event, windows::NamedPipe, Interest, Registry, Token};
use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use std::{
    cell::RefCell,
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::windows::prelude::{FromRawHandle, IntoRawHandle, OpenOptionsExt},
    rc::Rc,
    sync::{Arc, Mutex},
    vec::Vec,
};
use windows::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

fn server() -> io::Result<(NamedPipe, String)> {
    use rand::Rng;
    let num: u64 = rand::thread_rng().gen();
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

pub(crate) fn pipe() -> io::Result<(NamedPipe, NamedPipe)> {
    let (pipe, name) = server()?;
    Ok((pipe, client(&name)?))
}

/// A virtual TUN (IP) interface.
pub struct WinTunInterface {
    inner: Arc<wintun::Session>,
    mtu: usize,
    medium: Medium,
    pipe_server: Rc<RefCell<NamedPipe>>,
    pipe_client: Arc<Mutex<NamedPipe>>,
}

impl event::Source for WinTunInterface {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.pipe_server.borrow_mut().register(registry, token, interests)?;
        Ok(())
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.pipe_server.borrow_mut().reregister(registry, token, interests)?;
        Ok(())
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.pipe_server.borrow_mut().deregister(registry)?;
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

        let pipe_client = Arc::new(Mutex::new(pipe_client));

        // let inner = WinTunInterfaceDesc::new(name, medium)?;
        // let mtu = inner.interface_mtu()?;
        let mtu = 1500;
        Ok(WinTunInterface {
            inner,
            mtu,
            medium,
            pipe_server: Rc::new(RefCell::new(pipe_server)),
            pipe_client,
        })
    }

    pub fn pipe_client(&self) -> Arc<Mutex<NamedPipe>> {
        self.pipe_client.clone()
    }

    pub fn pipe_client_event(&self) -> Result<(), io::Error> {
        let mut buffer = vec![0; self.mtu];
        match self
            .pipe_client
            .lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .read(&mut buffer)
        {
            Ok(len) => {
                let write_pack = self.inner.allocate_send_packet(len as u16);
                if let Ok(mut write_pack) = write_pack {
                    write_pack.bytes_mut().copy_from_slice(&buffer[..len]);
                    self.inner.send_packet(write_pack);
                } else if let Err(err) = write_pack {
                    log::error!("phy: failed to allocate send packet: {}", err);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }
        Ok(())
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
        /*
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
        */

        let mut buffer = vec![0; self.mtu];
        match self.pipe_server.borrow_mut().read(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                let rx = RxToken { buffer };
                let tx = TxToken {
                    pipe_server: self.pipe_server.clone(),
                };
                Some((rx, tx))
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
            Err(err) => panic!("{}", err),
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            pipe_server: self.pipe_server.clone(),
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
    pipe_server: Rc<RefCell<NamedPipe>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);

        /*
        let inner = self.inner.clone();
        let write_pack = inner.allocate_send_packet(len as u16);
        if let Ok(mut write_pack) = write_pack {
            write_pack.bytes_mut().copy_from_slice(&buffer[..]);
            inner.send_packet(write_pack);
        } else if let Err(err) = write_pack {
            log::error!("phy: failed to allocate send packet: {}", err);
        }
         */

        match self.pipe_server.borrow_mut().write(&buffer[..]) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                log::trace!("phy: tx failed due to WouldBlock")
            }
            Err(err) => log::error!("{}", err),
        }
        result
    }
}

pub struct NamedPipeSource(pub Arc<Mutex<NamedPipe>>);

impl event::Source for NamedPipeSource {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .register(registry, token, interests)
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .deregister(registry)
    }
}
