/// Parts of the code below are Copyright (c) 2023, Conrad Kleinespel et al
///
/// This module contains code that was originally written by Conrad Kleinespel for the rpassword
/// crate. No copyright notices were found in the original code.
///
/// See: https://docs.rs/rpassword/latest/rpassword/
///
/// Most code was replaced and so is no longer a derived work; work that we kept:
///
/// - the "HiddenInput" struct and implementation, with changes:
///   * replaced occurences of explicit 'i32' and 'c_int' with RawFd
///   * open the TTY ourselves to mitigate Linux CVE-2023-2002
/// - the general idea of a "SafeString" type that clears its memory
///   (although much more robust than in the original code)
///
use std::io::{self, Error, ErrorKind, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::{fs, mem};

use libc::{tcsetattr, termios, ECHO, ECHONL, ICANON, TCSANOW, VERASE, VKILL};

use crate::cutils::cerr;

use super::securemem::PamBuffer;

struct TermConfig {
    tty: fs::File,
    term_orig: termios,
}

impl TermConfig {
    fn default() -> io::Result<Option<TermConfig>> {
        // FIXME pass in tty or stdin instead

        // control ourselves that we are really talking to a TTY
        // mitigates: https://marc.info/?l=oss-security&m=168164424404224
        let Ok(tty) = fs::File::open("/dev/tty") else {
            // if we have nothing to show, we have nothing to hide
            return Ok(None);
        };
        let fd = tty.as_raw_fd();

        let term_orig = safe_tcgetattr(fd)?;

        Ok(Some(TermConfig { tty, term_orig }))
    }

    fn new_hidden(feedback: bool) -> io::Result<Option<TermConfig>> {
        // FIXME pass in tty or stdin instead

        // control ourselves that we are really talking to a TTY
        // mitigates: https://marc.info/?l=oss-security&m=168164424404224
        let Ok(tty) = fs::File::open("/dev/tty") else {
            // if we have nothing to show, we have nothing to hide
            return Ok(None);
        };
        let fd = tty.as_raw_fd();

        // Make two copies of the terminal settings. The first one will be modified
        // and the second one will act as a backup for when we want to set the
        // terminal back to its original state.
        let mut term = safe_tcgetattr(fd)?;
        let term_orig = safe_tcgetattr(fd)?;

        // Hide the password. This is what makes this function useful.
        term.c_lflag &= !ECHO;

        // But don't hide the NL character when the user hits ENTER.
        term.c_lflag |= ECHONL;

        if feedback {
            // Disable canonical mode to read character by character when pwfeedback is enabled.
            term.c_lflag &= !ICANON;
        }

        // Save the settings for now.
        // SAFETY: we are passing tcsetattr a valid file descriptor and pointer-to-struct
        cerr(unsafe { tcsetattr(fd, TCSANOW, &term) })?;

        Ok(Some(TermConfig { tty, term_orig }))
    }
}

impl Drop for TermConfig {
    fn drop(&mut self) {
        // Set the the mode back to normal
        // SAFETY: we are passing tcsetattr a valid file descriptor and pointer-to-struct
        unsafe {
            tcsetattr(self.tty.as_raw_fd(), TCSANOW, &self.term_orig);
        }
    }
}

fn safe_tcgetattr(fd: RawFd) -> io::Result<termios> {
    let mut term = mem::MaybeUninit::<termios>::uninit();
    // SAFETY: we are passing tcgetattr a pointer to valid memory
    cerr(unsafe { ::libc::tcgetattr(fd, term.as_mut_ptr()) })?;
    // SAFETY: if the previous call was a success, `tcgetattr` has initialized `term`
    Ok(unsafe { term.assume_init() })
}

/// Reads a password from the given file descriptor
fn read_unbuffered(
    source: &mut dyn io::Read,
    sink: &mut dyn io::Write,
    term_config: &TermConfig,
    feedback: bool,
) -> io::Result<PamBuffer> {
    const BACKSPACE: u8 = 8;

    let mut password = PamBuffer::default();
    let mut i = 0;

    for read_byte in source.bytes() {
        let read_byte = read_byte?;

        if read_byte == b'\n' {
            if feedback {
                while i > 0 {
                    let _ = sink.write(&[BACKSPACE, b' ', BACKSPACE]);
                    i -= 1;
                }
            }
            sink.write(&[b'\n'])?;
            break;
        }

        if read_byte == term_config.term_orig.c_cc[VERASE] {
            if i > 0 {
                password[i - 1] = 0;
                i -= 1;
                if feedback {
                    sink.write(&[BACKSPACE, b' ', BACKSPACE])?;
                }
            }
        } else if read_byte == term_config.term_orig.c_cc[VKILL] {
            while i > 0 {
                password[i - 1] = 0;
                i -= 1;
                if feedback {
                    sink.write(&[BACKSPACE, b' ', BACKSPACE])?;
                }
            }
        } else {
            if feedback {
                sink.write(&[b'*'])?;
            }

            if let Some(dest) = password.get_mut(i) {
                *dest = read_byte;
                i += 1;
            } else {
                return Err(Error::new(
                    ErrorKind::OutOfMemory,
                    "incorrect password attempt",
                ));
            }
        }
    }

    Ok(password)
}

/// Write something and immediately flush
fn write_unbuffered(sink: &mut dyn io::Write, text: &str) -> io::Result<()> {
    sink.write_all(text.as_bytes())?;
    sink.flush()
}

/// A data structure representing either /dev/tty or /dev/stdin+stderr
pub enum Terminal<'a> {
    Tty(fs::File),
    StdIE(io::StdinLock<'a>, io::StderrLock<'a>),
}

impl Terminal<'_> {
    /// Open the current TTY for user communication
    pub fn open_tty() -> io::Result<Self> {
        Ok(Terminal::Tty(
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")?,
        ))
    }

    /// Open standard input and standard error for user communication
    pub fn open_stdie() -> io::Result<Self> {
        Ok(Terminal::StdIE(io::stdin().lock(), io::stderr().lock()))
    }

    /// Reads input with TTY echo disabled
    pub fn read_password(&mut self) -> io::Result<PamBuffer> {
        let (source, sink) = match self {
            Terminal::StdIE(x, y) => (x as &mut dyn io::Read, y as &mut dyn io::Write),
            Terminal::Tty(x) => (
                &mut &*x as &mut dyn io::Read,
                &mut &*x as &mut dyn io::Write,
            ),
        };

        let config = TermConfig::new_hidden(true)?;
        read_unbuffered(source, sink, &config.unwrap(), false)
    }

    /// Reads input with TTY echo disabled, but do provide visual feedback while typing.
    pub fn read_password_with_feedback(&mut self) -> io::Result<PamBuffer> {
        let (source, sink) = match self {
            Terminal::StdIE(x, y) => (x as &mut dyn io::Read, y as &mut dyn io::Write),
            Terminal::Tty(x) => (
                &mut &*x as &mut dyn io::Read,
                &mut &*x as &mut dyn io::Write,
            ),
        };

        let config = TermConfig::new_hidden(true)?;
        read_unbuffered(source, sink, &config.unwrap(), true)
    }

    /// Reads input with TTY echo enabled
    pub fn read_cleartext(&mut self) -> io::Result<PamBuffer> {
        let (source, sink) = match self {
            Terminal::StdIE(x, y) => (x as &mut dyn io::Read, y as &mut dyn io::Write),
            Terminal::Tty(x) => (
                &mut &*x as &mut dyn io::Read,
                &mut &*x as &mut dyn io::Write,
            ),
        };

        let config = TermConfig::default()?;
        read_unbuffered(source, sink, &config.unwrap(), true)
    }

    /// Display information
    pub fn prompt(&mut self, text: &str) -> io::Result<()> {
        write_unbuffered(self.sink(), text)
    }

    // boilerplate reduction functions
    fn source(&mut self) -> &mut dyn io::Read {
        match self {
            Terminal::StdIE(x, _) => x,
            Terminal::Tty(x) => x,
        }
    }

    fn sink(&mut self) -> &mut dyn io::Write {
        match self {
            Terminal::StdIE(_, x) => x,
            Terminal::Tty(x) => x,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{read_unbuffered, write_unbuffered};

    #[test]
    fn miri_test_read() {
        let mut data = "password123\nhello world".as_bytes();
        let buf = read_unbuffered(&mut data, false).unwrap();
        // check that the \n is not part of input
        assert_eq!(
            buf.iter()
                .map(|&b| b as char)
                .take_while(|&x| x != '\0')
                .collect::<String>(),
            "password123"
        );
        // check that the \n is also consumed but the rest of the input is still there
        assert_eq!(std::str::from_utf8(data).unwrap(), "hello world");
    }

    #[test]
    fn miri_test_longpwd() {
        assert!(read_unbuffered(&mut "a".repeat(511).as_bytes(), false).is_ok());
        assert!(read_unbuffered(&mut "a".repeat(512).as_bytes(), false).is_err());
    }

    #[test]
    fn miri_test_write() {
        let mut data = Vec::new();
        write_unbuffered(&mut data, "prompt").unwrap();
        assert_eq!(std::str::from_utf8(&data).unwrap(), "prompt");
    }
}
