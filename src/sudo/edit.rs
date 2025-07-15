use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::net::Shutdown;
use std::os::unix::{fs::OpenOptionsExt, net::UnixStream, process::ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{io, process};

use crate::system::file::{create_temporary_dir, FileLock};
use crate::system::wait::{Wait, WaitError, WaitOptions};
use crate::system::{fork, ForkResult};

pub(super) fn edit_file(path: &Path) {
    let editor: &OsStr = OsStr::new("/usr/bin/vim");

    // Open file
    let mut file: File = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();

    // Error for special files
    if !file.metadata().unwrap().is_file() {
        eprintln_ignore_io_error!("File {} is not a regular file", path.display());
        process::exit(1);
    }

    // Take file lock
    let lock = FileLock::exclusive(&file, true)
        .map_err(|err| {
            if err.kind() == io::ErrorKind::WouldBlock {
                err //io_msg!(err, "{} busy, try again later", sudoers_path.display())
            } else {
                err
            }
        })
        .unwrap();

    // Read file
    let mut old_data = Vec::new();
    file.read_to_end(&mut old_data).unwrap();

    // Create socket
    let (mut parent_socket, child_socket) = UnixStream::pair().unwrap();

    // Spawn child
    // SAFETY: There should be no other threads at this point.
    let ForkResult::Parent(command_pid) = unsafe { fork() }.unwrap() else {
        handle_child(child_socket, editor, path, old_data)
    };
    drop(child_socket);

    // Read from socket
    let data = read_len_prefix(&mut parent_socket).unwrap();

    // If child has error, exit with non-zero exit code
    let status = loop {
        match command_pid.wait(WaitOptions::new()) {
            Ok((_, status)) => break status,
            Err(WaitError::Io(err)) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => panic!("{err:?}"),
        }
    };
    assert!(status.did_exit());
    if let Some(signal) = status.term_signal() {
        process::exit(128 + signal);
    } else if let Some(code) = status.exit_status() {
        if code != 0 {
            process::exit(code);
        }
    } else {
        process::exit(1);
    }

    if data == old_data {
        // FIXME print message
        return;
    }

    // FIXME check if modified since reading and if so ask user what to do

    // Write file
    file.rewind().unwrap();
    file.write_all(&data).unwrap();
    file.set_len(data.len().try_into().unwrap()).unwrap();

    drop(lock);
}

struct TempDirDropGuard(PathBuf);

impl Drop for TempDirDropGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir(&self.0) {
            eprintln_ignore_io_error!(
                "Failed to remove temporary directory {}: {e}",
                self.0.display(),
            );
        };
    }
}

fn handle_child(socket: UnixStream, editor: &OsStr, path: &Path, old_data: Vec<u8>) -> ! {
    match handle_child_inner(socket, editor, path, old_data) {
        Ok(()) => process::exit(0),
        Err(err) => {
            eprintln_ignore_io_error!("{err}");
            process::exit(1);
        }
    }
}

// FIXME maybe use pipes once std::io::pipe has been stabilized long enough.
// This would allow getting rid of write_len_prefix and read_len_prefix.
fn handle_child_inner(
    mut socket: UnixStream,
    editor: &OsStr,
    path: &Path,
    old_data: Vec<u8>,
) -> Result<(), String> {
    // FIXME remove temporary directory when an error happens

    // Drop root privileges.
    unsafe {
        libc::setuid(libc::getuid());
    }

    let tempdir = TempDirDropGuard(
        create_temporary_dir().map_err(|e| format!("Failed to create temporary directory: {e}"))?,
    );

    // Create temp file
    let tempfile_path = tempdir
        .0
        .join(path.file_name().expect("file must have filename"));
    let mut tempfile = std::fs::File::create_new(&tempfile_path).map_err(|e| {
        format!(
            "Failed to create temporary file {}: {e}",
            tempfile_path.display(),
        )
    })?;

    // Write to temp file
    tempfile.write_all(&old_data).map_err(|e| {
        format!(
            "Failed to write to temporary file {}: {e}",
            tempfile_path.display(),
        )
    })?;
    drop(tempfile);

    // Spawn editor
    let status = Command::new(editor).arg(&tempfile_path).status().unwrap();
    if !status.success() {
        drop(tempdir);

        if let Some(signal) = status.signal() {
            process::exit(128 + signal);
        }
        process::exit(status.code().unwrap_or(1));
    }

    // Read from temp file
    let new_data = std::fs::read(&tempfile_path).map_err(|e| {
        format!(
            "Failed to read from temporary file {}: {e}",
            tempfile_path.display(),
        )
    })?;

    // FIXME preserve temporary file if the original couldn't be written to
    std::fs::remove_file(&tempfile_path).map_err(|e| {
        format!(
            "Failed to remove temporary file {}: {e}",
            tempfile_path.display(),
        )
    })?;

    // Check if the data actually changed. If not abort the edit operation.
    // And if empty, ask the user what to do.
    if new_data == old_data {
        process::exit(1);
    }

    if new_data.is_empty() {
        match crate::visudo::ask_response(
            format!("sudoedit: truncate {} to zero? (y/n) [n] ", path.display()).as_bytes(),
            b"yn",
        ) {
            Ok(b'y') => {}
            _ => {
                eprintln_ignore_io_error!("Not overwriting {}", path.display());
                process::exit(1)
            }
        }
    }

    // Write to socket
    write_len_prefix(&mut socket, &new_data)
        .map_err(|e| format!("Failed to write data to parent: {e}"))?;

    process::exit(0);
}

fn write_len_prefix(socket: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    socket.write_all(data)?;
    socket.shutdown(Shutdown::Both)?;
    Ok(())
}

fn read_len_prefix(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut new_data = Vec::new();
    socket.read_to_end(&mut new_data)?;
    Ok(new_data)
}
