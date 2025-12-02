use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

use libc::O_CLOEXEC;

use crate::cutils::cerr;

pub(crate) fn make_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    // Create socket
    let mut pipes = [-1, -1];
    // SAFETY: A valid pointer to a mutable array of 2 fds is passed in.
    unsafe {
        cerr(libc::pipe2(pipes.as_mut_ptr(), O_CLOEXEC)).unwrap();
    }
    // SAFETY: pipe2 created two owned pipe fds
    unsafe {
        Ok((
            OwnedFd::from_raw_fd(pipes[0]),
            OwnedFd::from_raw_fd(pipes[1]),
        ))
    }
}
