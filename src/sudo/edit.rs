use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::{io, process};

use crate::system::file::{create_temporary_dir, FileLock};
use crate::system::wait::{Wait, WaitError, WaitOptions};
use crate::system::{fork, ForkResult};

pub(super) fn edit_file(path: &Path) {
    // FIXME check symlinks and parent directory permissions

    let editor: &OsStr = OsStr::new("/usr/bin/vim");

    // Take file lock
    let mut file: File = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();

    let lock = FileLock::exclusive(&file, true)
        .map_err(|err| {
            if err.kind() == io::ErrorKind::WouldBlock {
                err //io_msg!(err, "{} busy, try again later", sudoers_path.display())
            } else {
                err
            }
        })
        .unwrap();

    // FIXME check file is not device file

    // Read file
    let mut old_data = Vec::new();
    file.read_to_end(&mut old_data).unwrap();

    // Create socket
    let (mut parent_socket, child_socket) = UnixStream::pair().unwrap();

    // Spawn child
    // SAFETY: There should be no other threads at this point.
    let ForkResult::Parent(command_pid) = unsafe { fork() }.unwrap() else {
        let filename = path.file_name().expect("file must have filename");
        handle_child(child_socket, editor, filename, old_data)
    };

    // Read from socket
    let data = read_len_prefix(&mut parent_socket).unwrap();
    println_ignore_io_error!("{data:?}");

    // If child has error, exit with non-zero exit code
    let status = loop {
        match command_pid.wait(WaitOptions::new()) {
            Ok((_, status)) => break status,
            Err(WaitError::Io(err)) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => panic!("{err:?}"),
        }
    };
    assert!(status.did_exit());
    if status.term_signal().is_some() {
        process::exit(2);
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

// FIXME maybe use pipes once std::io::pipe has been stabilized long enough.
// This would allow getting rid of write_len_prefix and read_len_prefix.
fn handle_child(mut socket: UnixStream, editor: &OsStr, filename: &OsStr, old_data: Vec<u8>) -> ! {
    // FIXME remove temporary directory when an error happens

    // Drop root privileges.
    unsafe {
        libc::setuid(libc::getuid());
    }

    let tempdir = create_temporary_dir().unwrap_or_else(|e| {
        eprintln_ignore_io_error!("Failed to create temporary directory: {e}");
        process::exit(1);
    });

    // Create temp file
    let tempfile_path = tempdir.join(filename);
    let mut tempfile = std::fs::File::create_new(&tempfile_path).unwrap_or_else(|e| {
        eprintln_ignore_io_error!(
            "Failed to create temporary file {}: {e}",
            tempfile_path.display(),
        );
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
        if status.signal().is_some() {
            process::exit(2);
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

    // FIXME preserve temporary file if the original couldn't be written to
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

    // Check if the data actually changed. If not abort the edit operation.
    // And if empty, ask the user what to do.

    // Write to socket
    write_len_prefix(&mut socket, &new_data).unwrap_or_else(|e| {
        eprintln_ignore_io_error!("Failed to write data to parent: {e}");
        process::exit(1);
    });

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
