use std::ffi::{c_char, CStr, OsStr};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::{io, mem, process};

use crate::system::interface::ProcessId;
use crate::system::{fork, ForkResult};

pub(super) fn edit_file(file: &Path) {
    // Check symlinks and parent directory permissions
    // Take file lock
    // Check file is not device file
    // Read file

    // Create socket
    // Spawn child
    // Write to socket

    // Read from socket
    // If child has error, exit with non-zero exit code
    // Write file
}

fn fork_child(editor: &OsStr, filename: &OsStr) -> (ProcessId, UnixStream) {
    let (parent_socket, child_socket) = UnixStream::pair().unwrap();

    // SAFETY: There should be no other threads at this point.
    let ForkResult::Parent(command_pid) = unsafe { fork() }.unwrap() else {
        handle_child(child_socket, editor, filename)
    };

    (command_pid, parent_socket)
}

// FIXME maybe use pipes once std::io::pipe has been stabilized long enough.
// This would allow getting rid of write_len_prefix and read_len_prefix.
fn handle_child(mut socket: UnixStream, editor: &OsStr, filename: &OsStr) -> ! {
    // Drop root privileges.
    unsafe {
        libc::setuid(libc::getuid());
    }

    // Create temp directory
    // XXX(bjorn3): This uses mkdtemp from libc as rust doesn't have a random
    // number generator as part of libstd, so we need unsafe either way on some
    // of the platforms we support if we don't want to add another dependency.
    // mkdtemp should be robust on all platforms we support. The only case I'm
    // aware of where mkdtemp is broken is MinGW, but we don't support Windows
    // anyway.
    // FIXME maybe revisit this choice once libstd exposes some stable way to
    // get random numbers?
    let mut template = *b"sudo-rsXXXXXX";
    let tempdir_ptr = unsafe { libc::mkdtemp(template.as_mut_ptr().cast::<c_char>()) };
    if tempdir_ptr.is_null() {
        eprintln_ignore_io_error!(
            "Failed to create temporary directory: {}",
            io::Error::last_os_error()
        );
        process::exit(1);
    }
    let tempdir = Path::new(OsStr::from_bytes(
        unsafe { CStr::from_ptr(tempdir_ptr) }.to_bytes(),
    ))
    .to_owned();
    unsafe {
        libc::free(tempdir_ptr.cast());
    }

    // Create temp file
    let tempfile_path = tempdir.join(filename);
    let mut tempfile = std::fs::File::create_new(&tempfile_path).unwrap_or_else(|e| {
        eprintln_ignore_io_error!(
            "Failed to create temporary file {}: {e}",
            tempfile_path.display(),
        );
        process::exit(1);
    });

    // Read from socket
    let old_data = read_len_prefix(&mut socket).unwrap_or_else(|e| {
        eprintln_ignore_io_error!("Failed to read data from parent: {e}");
        process::exit(1);
    });

    // Write to temp file
    tempfile.write_all(&old_data).unwrap_or_else(|e| {
        eprintln_ignore_io_error!(
            "Failed to write to temporary file {}: {e}",
            tempfile_path.display(),
        );
        process::exit(1);
    });
    drop(tempfile);

    // Spawn editor
    let status = Command::new(editor).arg(&tempfile_path).status().unwrap();
    if !status.success() {
        if let Some(signal) = status.signal() {
            // If the editor aborted due to a signal, try to abort with the same signal.
            unsafe {
                libc::raise(signal);
            }
            // If the signal was not fatal for us, we continue executing. In that case we
            // use exit code 1.
        }
        process::exit(status.code().unwrap_or(1));
    }

    // Read from temp file
    let new_data = std::fs::read(&tempfile_path).unwrap_or_else(|e| {
        eprintln_ignore_io_error!(
            "Failed to read from temporary file {}: {e}",
            tempfile_path.display(),
        );
        process::exit(1);
    });
    std::fs::remove_file(&tempfile_path).unwrap_or_else(|e| {
        eprintln_ignore_io_error!(
            "Failed to remove temporary file {}: {e}",
            tempfile_path.display(),
        );
        process::exit(1);
    });
    std::fs::remove_dir(&tempdir).unwrap_or_else(|e| {
        eprintln_ignore_io_error!(
            "Failed to remove temporary directory {}: {e}",
            tempdir.display(),
        );
        process::exit(1);
    });

    // Write to socket
    write_len_prefix(&mut socket, &new_data).unwrap_or_else(|e| {
        eprintln_ignore_io_error!("Failed to write data to parent: {e}");
        process::exit(1);
    });

    process::exit(0);
}

fn write_len_prefix(socket: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    socket.write_all(&usize::to_ne_bytes(data.len()))?;
    socket.write_all(data)?;
    Ok(())
}

fn read_len_prefix(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; mem::size_of::<usize>()];
    socket.read_exact(&mut len)?;
    let mut old_data = vec![0; usize::from_ne_bytes(len)];
    socket.read_exact(&mut old_data)?;
    Ok(old_data)
}
