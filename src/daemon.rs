//! Minimal Unix daemonization, replacing the `daemonize` crate (0.5.0).
//!
//! Reproduces exactly the sequence `daemonize::Daemonize::start()` performed with the options
//! tun2proxy used (`working_directory`, `umask`, `stdout`, `stderr`; no pid file, user, group or
//! chroot):
//!
//! 1. `fork()`; the original process `waitpid()`s the first child and exits with the raw wait
//!    status (as `daemonize` did);
//! 2. first child: `chdir(dir)`, `setsid()`, `umask(mask)`, `fork()` again and exit(0);
//! 3. grandchild: stdin -> `/dev/null`, stdout/stderr -> the given files, then return `Ok(())`.
#![cfg(unix)]

use std::ffi::CString;
use std::fs::File;
use std::io::{Error, Result};
use std::os::unix::{ffi::OsStrExt, io::AsRawFd};
use std::path::Path;

fn check(ret: libc::c_int, what: &str) -> Result<libc::c_int> {
    if ret == -1 {
        let e = Error::last_os_error();
        Err(Error::new(e.kind(), format!("{what}: {e}")))
    } else {
        Ok(ret)
    }
}

/// Detach from the terminal. Returns only in the final daemon process; the original process and
/// the intermediate child exit inside this call.
pub fn daemonize<P: AsRef<Path>>(working_directory: P, umask: libc::mode_t, stdout: File, stderr: File) -> Result<()> {
    unsafe {
        let pid = check(libc::fork(), "fork")?;
        if pid != 0 {
            let mut status: libc::c_int = 0;
            check(libc::waitpid(pid, &mut status, 0), "waitpid")?;
            std::process::exit(status);
        }

        let dir = CString::new(working_directory.as_ref().as_os_str().as_bytes())
            .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "working directory contains NUL"))?;
        check(libc::chdir(dir.as_ptr()), "chdir")?;
        check(libc::setsid(), "setsid")?;
        libc::umask(umask);

        if check(libc::fork(), "fork")? != 0 {
            std::process::exit(0);
        }

        let devnull = check(libc::open(c"/dev/null".as_ptr(), libc::O_RDWR), "open /dev/null")?;
        check(libc::dup2(devnull, libc::STDIN_FILENO), "redirect stdin")?;
        check(libc::dup2(stdout.as_raw_fd(), libc::STDOUT_FILENO), "redirect stdout")?;
        check(libc::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO), "redirect stderr")?;
        check(libc::close(devnull), "close /dev/null")?;
    }
    Ok(())
}
