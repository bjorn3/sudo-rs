use std::io::{self, PipeReader, PipeWriter};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{self, Command};

use crate::log::user_error;
use crate::system::interface::ProcessId;
use crate::system::{ForkResult, fork, mark_fds_as_cloexec};

pub(super) fn spawn_askpass(program: &Path, prompt: &str) -> io::Result<(ProcessId, PipeReader)> {
    // Create socket
    let (pipe_read, pipe_write) = io::pipe()?;

    // Spawn child
    // SAFETY: There should be no other threads at this point.
    let ForkResult::Parent(command_pid) = unsafe { fork() }.unwrap() else {
        drop(pipe_read);
        handle_child(program, prompt, pipe_write)
    };
    drop(pipe_write);

    Ok((command_pid, pipe_read))
}

fn handle_child(program: &Path, prompt: &str, stdout: PipeWriter) -> ! {
    // Drop root privileges.
    // SAFETY: setuid does not change any memory and only affects OS state.
    unsafe {
        libc::setuid(libc::getuid());
    }

    if let Err(e) = mark_fds_as_cloexec() {
        eprintln_ignore_io_error!("Failed to mark fds as CLOEXEC: {e}");
        process::exit(1);
    };

    // Exec askpass program
    let error = Command::new(program).arg(prompt).stdout(stdout).exec();
    user_error!(
        "Failed to run askpass program {path}: {error}",
        path = program.display(),
        error = error
    );
    process::exit(1);
}
