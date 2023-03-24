#[derive(Debug)]
pub struct Error {
    message: String,
}

pub fn s2e(s: &str) -> Error {
    Error::from(s)
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<smoltcp::iface::RouteTableFull> for Error {
    fn from(err: smoltcp::iface::RouteTableFull) -> Self {
        Self {
            message: format!("{err:?}"),
        }
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self { message: err }
    }
}

impl From<&String> for Error {
    fn from(err: &String) -> Self {
        Self {
            message: err.to_string(),
        }
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
