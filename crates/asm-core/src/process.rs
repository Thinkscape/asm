//! Bounded, cancellable collection of a child process group's output.

use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

use crate::error::{CoreError, Result};

pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(25);
pub(crate) const STREAM_LIMIT: usize = 64 * 1024;

/// Operator-facing messages for one kind of external program.
pub(crate) struct OutputErrors {
    pub read: &'static str,
    pub timeout: &'static str,
    pub capture: &'static str,
    pub too_large: &'static str,
}

pub(crate) struct ProcessGroup {
    child: Child,
    reaped: bool,
}

impl ProcessGroup {
    fn exited(&self) -> io::Result<bool> {
        // SAFETY: waitid writes this siginfo for our direct child. WNOWAIT keeps the
        // process-group ID reserved until cleanup has signalled all descendants.
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let ret = libc::waitid(libc::P_PID, self.child.id() as _, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT);
            if ret == 0 { Ok(info.si_pid() != 0) } else { Err(io::Error::last_os_error()) }
        }
    }

    fn kill(&self) {
        // SAFETY: process_group(0) made the child's PID its process-group ID. Only
        // signal while the child has not been reaped, so the ID cannot be reused.
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL); }
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill();
            let _ = self.wait();
        }
    }
}

/// Collect stdout and stderr of a child started with `process_group(0)` and piped
/// output, killing its whole group on exit, timeout, cancellation or error.
pub(crate) fn collect_output(
    child: Child, timeout: Duration, check_cancelled: impl Fn() -> Result<()>, errors: &OutputErrors,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let output_error = || CoreError::vault_unavailable(errors.read);
    let mut process = ProcessGroup { child, reaped: false };
    let mut stdout = process.child.stdout.take().ok_or_else(output_error)?;
    let mut stderr = process.child.stderr.take().ok_or_else(output_error)?;
    let mut fds = [pollable(stdout.as_raw_fd(), errors)?, pollable(stderr.as_raw_fd(), errors)?];
    let mut out = Vec::new();
    let mut err = Vec::new();
    let start = Instant::now();
    loop {
        check_cancelled()?;
        let remaining = timeout.checked_sub(start.elapsed())
            .ok_or_else(|| CoreError::vault_unavailable(errors.timeout))?;
        let millis = remaining.min(POLL_INTERVAL).as_millis().max(1) as i32;
        // SAFETY: fds is a live fixed-size array of pollfd for this call.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
        if ready == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { continue; }
            return Err(output_error());
        }
        if fds[0].revents != 0 && drain(&mut stdout, &mut out, errors)? { fds[0].fd = -1; }
        if fds[1].revents != 0 && drain(&mut stderr, &mut err, errors)? { fds[1].fd = -1; }
        match process.exited() {
            Ok(true) => {
                process.kill();
                // The leader will not write any more; collect data already in its pipes.
                drain(&mut stdout, &mut out, errors)?;
                drain(&mut stderr, &mut err, errors)?;
                return Ok((process.wait().map_err(|_| output_error())?, out, err));
            }
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(output_error()),
        }
    }
}

fn pollable(fd: RawFd, errors: &OutputErrors) -> Result<libc::pollfd> {
    // SAFETY: the caller owns this pipe descriptor, set nonblocking for bounded reads.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        return Err(CoreError::vault_unavailable(errors.capture));
    }
    Ok(libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
}

fn drain(pipe: &mut impl Read, output: &mut Vec<u8>, errors: &OutputErrors) -> Result<bool> {
    let mut buffer = [0u8; 8192];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(len) if output.len() + len <= STREAM_LIMIT => output.extend_from_slice(&buffer[..len]),
            Ok(_) => return Err(CoreError::vault_unavailable(errors.too_large)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(CoreError::vault_unavailable(errors.read)),
        }
    }
}
