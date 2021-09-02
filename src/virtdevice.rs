use smoltcp::phy;
use smoltcp::phy::{Device, DeviceCapabilities};
use smoltcp::time::Instant;

#[derive(Default)]
pub struct VirtualTunDevice {
    capabilities: DeviceCapabilities,
    inbuf: Vec<Vec<u8>>,
    outbuf: Vec<Vec<u8>>
}


impl VirtualTunDevice {
    pub fn inject_packet(self: &mut Self, buffer: &[u8]) {
        let vec = Vec::from(buffer);
        self.inbuf.push(vec);
    }

    pub fn exfiltrate_packet(self: &mut Self, ) -> Option<Vec<u8>> {
        self.outbuf.pop()
    }
}

pub struct VirtRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for VirtRxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
        where
            F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer[..])
    }
}

pub struct VirtTxToken<'a>(&'a mut VirtualTunDevice);

impl<'a> phy::TxToken for VirtTxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
        where
            F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.0.outbuf.push(Vec::from(buffer));
        result
    }
}

impl<'a> Device<'a> for VirtualTunDevice {
    type RxToken = VirtRxToken;
    type TxToken = VirtTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if let Some(buffer) = self.inbuf.pop() {
            let rx = Self::RxToken { buffer };
            let tx = VirtTxToken(self);
            return Some((rx, tx));
        }
        None
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        return Some(VirtTxToken(self));
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

impl<'a> VirtualTunDevice {
    pub fn new(capabilities: DeviceCapabilities) -> Self {
        Self {
            capabilities,
            ..Default::default()
        }
    }
}