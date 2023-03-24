#[derive(Debug)]
pub struct Error {
    message: String,
}

pub fn s2e(s: &str) -> Error {
    Error::from(s)
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        From::<String>::from(err.to_string())
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Self {
        From::<String>::from(err.to_string())
    }
}

impl From<smoltcp::iface::RouteTableFull> for Error {
    fn from(err: smoltcp::iface::RouteTableFull) -> Self {
        From::<String>::from(format!("{err:?}"))
    }
}

impl From<smoltcp::socket::tcp::RecvError> for Error {
    fn from(err: smoltcp::socket::tcp::RecvError) -> Self {
        From::<String>::from(format!("{err:?}"))
    }
}

impl From<smoltcp::socket::tcp::ListenError> for Error {
    fn from(err: smoltcp::socket::tcp::ListenError) -> Self {
        From::<String>::from(format!("{err:?}"))
    }
}

impl From<smoltcp::socket::udp::BindError> for Error {
    fn from(err: smoltcp::socket::udp::BindError) -> Self {
        From::<String>::from(format!("{err:?}"))
    }
}

impl From<smoltcp::socket::tcp::SendError> for Error {
    fn from(err: smoltcp::socket::tcp::SendError) -> Self {
        From::<String>::from(format!("{err:?}"))
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        From::<String>::from(err.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self { message: err }
    }
}

impl From<&String> for Error {
    fn from(err: &String) -> Self {
        From::<String>::from(err.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        &self.message
    }
}
