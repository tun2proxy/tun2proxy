use smoltcp::{
    phy::{self, Device, DeviceCapabilities},
    time::Instant,
};

/// Virtual device representing the remote proxy server.
#[derive(Default)]
pub struct VirtualTunDevice {
    capabilities: DeviceCapabilities,
    inbuf: Vec<Vec<u8>>,
    outbuf: Vec<Vec<u8>>,
}

impl VirtualTunDevice {
    pub fn inject_packet(&mut self, buffer: &[u8]) {
        self.inbuf.push(buffer.to_vec());
    }

    pub fn exfiltrate_packet(&mut self) -> Option<Vec<u8>> {
        self.outbuf.pop()
    }
}

pub struct VirtRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for VirtRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..])
    }
}

pub struct VirtTxToken<'a>(&'a mut VirtualTunDevice);

impl<'a> phy::TxToken for VirtTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.0.outbuf.push(buffer);
        result
    }
}

impl Device for VirtualTunDevice {
    type RxToken<'a> = VirtRxToken;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.inbuf.pop() {
            let rx = Self::RxToken { buffer };
            let tx = VirtTxToken(self);
            return Some((rx, tx));
        }
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        return Some(VirtTxToken(self));
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

impl VirtualTunDevice {
    pub fn new(capabilities: DeviceCapabilities) -> Self {
        Self {
            capabilities,
            ..VirtualTunDevice::default()
        }
    }
}
