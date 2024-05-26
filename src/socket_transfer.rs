#![cfg(target_os = "linux")]

use crate::{error, SocketDomain, SocketProtocol};
use nix::{
    errno::Errno,
    fcntl::{self, FdFlag},
    sys::socket::{cmsg_space, getsockopt, recvmsg, sendmsg, sockopt, ControlMessage, ControlMessageOwned, MsgFlags, SockType},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{ErrorKind, IoSlice, IoSliceMut, Result},
    ops::DerefMut,
    os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
};
use tokio::net::{TcpSocket, UdpSocket, UnixDatagram};

const REQUEST_BUFFER_SIZE: usize = 64;

#[derive(Hash, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct Request {
    protocol: SocketProtocol,
    domain: SocketDomain,
    number: u32,
}

#[derive(Hash, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
enum Response {
    Ok,
}

/// Reconstruct socket from raw `fd`
pub fn reconstruct_socket(fd: RawFd) -> Result<OwnedFd> {
    // Check if `fd` is valid
    let fd_flags = fcntl::fcntl(fd, fcntl::F_GETFD)?;

    // `fd` is confirmed to be valid so it should be closed
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };

    // Insert CLOEXEC flag to the `fd` to prevent further propagation across `execve(2)` calls
    let mut fd_flags = FdFlag::from_bits(fd_flags).ok_or(ErrorKind::Unsupported)?;
    if !fd_flags.contains(FdFlag::FD_CLOEXEC) {
        fd_flags.insert(FdFlag::FD_CLOEXEC);
        fcntl::fcntl(fd, fcntl::F_SETFD(fd_flags))?;
    }

    Ok(socket)
}

/// Reconstruct transfer socket from `fd`
///
/// Panics if called outside of tokio runtime
pub fn reconstruct_transfer_socket(fd: OwnedFd) -> Result<UnixDatagram> {
    // Check if socket of type DATAGRAM
    let sock_type = getsockopt(&fd, sockopt::SockType)?;
    if !matches!(sock_type, SockType::Datagram) {
        return Err(ErrorKind::InvalidInput.into());
    }

    let std_socket: std::os::unix::net::UnixDatagram = fd.into();
    std_socket.set_nonblocking(true)?;

    // Fails if tokio context is absent
    Ok(UnixDatagram::from_std(std_socket).unwrap())
}

/// Create pair of interconnected sockets one of which is set to stay open across `execve(2)` calls.
pub async fn create_transfer_socket_pair() -> std::io::Result<(UnixDatagram, OwnedFd)> {
    let (local, remote) = tokio::net::UnixDatagram::pair()?;

    let remote_fd: OwnedFd = remote.into_std().unwrap().into();

    // Get `remote_fd` flags
    let fd_flags = fcntl::fcntl(remote_fd.as_raw_fd(), fcntl::F_GETFD)?;

    // Remove CLOEXEC flag from the `remote_fd` to allow propagating across `execve(2)`
    let mut fd_flags = FdFlag::from_bits(fd_flags).ok_or(ErrorKind::Unsupported)?;
    fd_flags.remove(FdFlag::FD_CLOEXEC);
    fcntl::fcntl(remote_fd.as_raw_fd(), fcntl::F_SETFD(fd_flags))?;

    Ok((local, remote_fd))
}

pub trait TransferableSocket: Sized {
    fn from_fd(fd: OwnedFd) -> Result<Self>;
    fn domain() -> SocketProtocol;
}

impl TransferableSocket for TcpSocket {
    fn from_fd(fd: OwnedFd) -> Result<Self> {
        // Check if socket is of type STREAM
        let sock_type = getsockopt(&fd, sockopt::SockType)?;
        if !matches!(sock_type, SockType::Stream) {
            return Err(ErrorKind::InvalidInput.into());
        }

        let std_stream: std::net::TcpStream = fd.into();
        std_stream.set_nonblocking(true)?;

        Ok(TcpSocket::from_std_stream(std_stream))
    }

    fn domain() -> SocketProtocol {
        SocketProtocol::Tcp
    }
}

impl TransferableSocket for UdpSocket {
    /// Panics if called outside of tokio runtime
    fn from_fd(fd: OwnedFd) -> Result<Self> {
        // Check if socket is of type DATAGRAM
        let sock_type = getsockopt(&fd, sockopt::SockType)?;
        if !matches!(sock_type, SockType::Datagram) {
            return Err(ErrorKind::InvalidInput.into());
        }

        let std_socket: std::net::UdpSocket = fd.into();
        std_socket.set_nonblocking(true)?;

        Ok(UdpSocket::try_from(std_socket).unwrap())
    }

    fn domain() -> SocketProtocol {
        SocketProtocol::Udp
    }
}

/// Send [`Request`] to `socket` and return received [`TransferableSocket`]s
///
/// Panics if called outside of tokio runtime
pub async fn request_sockets<S, T>(mut socket: S, domain: SocketDomain, number: u32) -> error::Result<Vec<T>>
where
    S: DerefMut<Target = UnixDatagram>,
    T: TransferableSocket,
{
    // Borrow socket as mut to prevent multiple simultaneous requests
    let socket = socket.deref_mut();

    // Send request
    let request = bincode::serialize(&Request {
        protocol: T::domain(),
        domain,
        number,
    })?;

    socket.send(&request[..]).await?;

    // Receive response
    loop {
        socket.readable().await?;

        let mut buf = [0_u8; REQUEST_BUFFER_SIZE];
        let mut iov = [IoSliceMut::new(&mut buf[..])];
        let mut cmsg = Vec::with_capacity(cmsg_space::<RawFd>() * number as usize);

        let msg = recvmsg::<()>(socket.as_fd().as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::empty());

        let msg = match msg {
            Err(Errno::EAGAIN) => continue,
            msg => msg?,
        };

        // Parse response
        let response = &msg.iovs().next().unwrap()[..msg.bytes];
        let response: Response = bincode::deserialize(response)?;
        if !matches!(response, Response::Ok) {
            return Err("Request for new sockets failed".into());
        }

        // Process received file descriptors
        let mut sockets = Vec::<T>::with_capacity(number as usize);
        for cmsg in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                for fd in fds {
                    if fd < 0 {
                        return Err("Received socket is invalid".into());
                    }

                    let owned_fd = reconstruct_socket(fd)?;
                    sockets.push(T::from_fd(owned_fd)?);
                }
            }
        }

        return Ok(sockets);
    }
}

/// Process [`Request`]s received from `socket`
///
/// Panics if called outside of tokio runtime
pub async fn process_socket_requests(socket: &UnixDatagram) -> error::Result<()> {
    loop {
        let mut buf = [0_u8; REQUEST_BUFFER_SIZE];

        let len = socket.recv(&mut buf[..]).await?;

        let request: Request = bincode::deserialize(&buf[..len])?;

        let response = Response::Ok;
        let buf = bincode::serialize(&response)?;

        let mut owned_fd_buf: Vec<OwnedFd> = Vec::with_capacity(request.number as usize);
        for _ in 0..request.number {
            let fd = match request.protocol {
                SocketProtocol::Tcp => match request.domain {
                    SocketDomain::IpV4 => tokio::net::TcpSocket::new_v4(),
                    SocketDomain::IpV6 => tokio::net::TcpSocket::new_v6(),
                }
                .map(|s| unsafe { OwnedFd::from_raw_fd(s.into_raw_fd()) }),
                SocketProtocol::Udp => match request.domain {
                    SocketDomain::IpV4 => tokio::net::UdpSocket::bind("0.0.0.0:0").await,
                    SocketDomain::IpV6 => tokio::net::UdpSocket::bind("[::]:0").await,
                }
                .map(|s| s.into_std().unwrap().into()),
            };
            match fd {
                Err(err) => log::warn!("Failed to allocate socket: {err}"),
                Ok(fd) => owned_fd_buf.push(fd),
            };
        }

        socket.writable().await?;

        let raw_fd_buf: Vec<RawFd> = owned_fd_buf.iter().map(|fd| fd.as_raw_fd()).collect();
        let cmsg = ControlMessage::ScmRights(&raw_fd_buf[..]);
        let iov = [IoSlice::new(&buf[..])];

        sendmsg::<()>(socket.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None)?;
    }
}
