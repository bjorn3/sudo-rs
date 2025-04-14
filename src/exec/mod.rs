mod event;
mod io_util;
mod no_pty;
mod use_pty;

use std::{
    borrow::Cow,
    env,
    ffi::{c_int, OsStr},
    io,
    os::unix::ffi::OsStrExt,
    os::unix::process::CommandExt,
    path::Path,
    process::Command,
    time::Duration,
};

use crate::{
    exec::no_pty::exec_no_pty,
    log::{dev_info, dev_warn, user_error},
    system::{
        interface::ProcessId,
        killpg,
        signal::{consts::*, signal_name},
        wait::{Wait, WaitError, WaitOptions},
    },
    system::{kill, set_target_user, signal::SignalNumber, term::UserTerm, Group, User},
};

use self::{
    event::{EventRegistry, Process},
    io_util::was_interrupted,
    use_pty::{exec_pty, SIGCONT_BG, SIGCONT_FG},
};

pub struct RunOptions<'a> {
    pub command: &'a Path,
    pub arguments: &'a [String],
    pub arg0: Option<&'a Path>,
    pub chdir: Option<&'a Path>,
    pub is_login: bool,
    pub user: &'a User,
    pub group: &'a Group,

    pub use_pty: bool,
    pub noexec: bool,
}

mod noexec {
    // On Linux we can use a seccomp() filter to disable exec.

    #[cfg(not(target_os = "linux"))]
    compile_error!("sudo_noexec shouldn't be compiled for non-Linux systems");

    use std::cmp;
    use std::mem::offset_of;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::ptr::addr_of;

    use libc::{
        c_int, c_uint, c_ulong, calloc, close, fork, ioctl, prctl, seccomp_data, seccomp_notif,
        seccomp_notif_resp, seccomp_notif_sizes, sock_filter, sock_fprog, syscall, SYS_execve,
        SYS_execveat, SYS_seccomp, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JUMP, BPF_K, BPF_LD, BPF_RET,
        BPF_STMT, PR_SET_NO_NEW_PRIVS, SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_GET_NOTIF_SIZES,
        SECCOMP_RET_ALLOW, SECCOMP_SET_MODE_FILTER, SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };

    const SECCOMP_RET_USER_NOTIF: c_uint = 0x7fc00000;
    const SECCOMP_IOCTL_NOTIF_RECV: c_ulong = 0xc0502100;
    const SECCOMP_IOCTL_NOTIF_SEND: c_ulong = 0xc0182101;

    unsafe fn seccomp<T>(operation: c_uint, flags: c_uint, args: *mut T) -> c_int {
        unsafe { syscall(SYS_seccomp, operation, flags, args) as c_int }
    }

    //#[used]
    //#[unsafe(link_section = ".init_array")]
    //static NOEXEC_CTOR: extern "C" fn() = noexec_ctor;

    pub fn add_noexec_filter(command: &mut Command) {
        unsafe {
            command.pre_exec(|| {
                // SAFETY: libc unnecessarily marks these functions as unsafe
                let exec_filter: [sock_filter; 5] = [
                    // Load syscall number into the accumulator
                    BPF_STMT((BPF_LD | BPF_ABS) as _, offset_of!(seccomp_data, nr) as _),
                    // Jump to user notify for execve/execveat
                    BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as _, SYS_execve as _, 2, 0),
                    BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as _, SYS_execveat as _, 1, 0),
                    // Allow non-matching syscalls
                    BPF_STMT((BPF_RET | BPF_K) as _, SECCOMP_RET_ALLOW),
                    // Notify sudo about execve/execveat syscall
                    BPF_STMT((BPF_RET | BPF_K) as _, SECCOMP_RET_USER_NOTIF as _),
                ];

                let exec_fprog = sock_fprog {
                    len: 5,
                    filter: addr_of!(exec_filter) as *mut sock_filter,
                };

                // SAFETY: Trivially safe as it doesn't touch any memory.
                // SECCOMP_SET_MODE_FILTER will fail unless the process has
                // CAP_SYS_ADMIN or the no_new_privs bit is set.
                if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(todo!());
                }

                // While the man page warns againt using seccomp_unotify as security
                // mechanism, the TOCTOU problem that is described there isn't
                // relevant here. We only SECCOMP_USER_NOTIF_FLAG_CONTINUE the first
                // execve which is done by ourself and thus trusted.
                // FIXME handle error
                // SAFETY: Passes a valid sock_fprog as argument.
                let notify_fd = seccomp(
                    SECCOMP_SET_MODE_FILTER,
                    SECCOMP_FILTER_FLAG_NEW_LISTENER as _,
                    &exec_fprog as *const sock_fprog as *mut sock_fprog,
                );
                if fork() == 0 {
                    close(notify_fd);
                    Ok(())
                } else {
                    let mut sizes = seccomp_notif_sizes {
                        seccomp_notif: 0,
                        seccomp_notif_resp: 0,
                        seccomp_data: 0,
                    };
                    if seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &mut sizes) == -1 {
                        libc::abort();
                    }

                    let req = calloc(
                        1,
                        cmp::max(sizes.seccomp_notif.into(), size_of::<seccomp_notif>()),
                    )
                    .cast::<seccomp_notif>();
                    let resp = calloc(
                        1,
                        cmp::max(
                            sizes.seccomp_notif_resp.into(),
                            size_of::<seccomp_notif_resp>(),
                        ),
                    )
                    .cast::<seccomp_notif_resp>();
                    if req.is_null() || resp.is_null() {
                        libc::abort();
                    }

                    // FIXME handle error
                    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req);

                    (*resp).id = (*req).id;
                    (*resp).val = 0;
                    (*resp).error = 0;
                    (*resp).flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;

                    // FIXME handle error
                    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);

                    // Exit the helper process after the target process has been
                    // exec'ed. This will close the seccomp_unotify fd after which
                    // all SECCOMP_RET_USER_NOTIF will result in ENOSYS

                    // FIXME return EACCESS rather than ENOSYS.
                    libc::exit(0);
                }
            });
        }
    }
}

/// Based on `ogsudo`s `exec_pty` function.
///
/// Returns the [`ExitReason`] of the command and a function that restores the default handler for
/// signals once its called.
pub fn run_command(
    options: RunOptions<'_>,
    env: impl IntoIterator<Item = (impl AsRef<OsStr>, impl AsRef<OsStr>)>,
) -> io::Result<ExitReason> {
    // FIXME: should we pipe the stdio streams?
    let qualified_path = options.command;
    let mut command = Command::new(qualified_path);
    // reset env and set filtered environment
    command.args(options.arguments).env_clear().envs(env);
    // set the arg0 to the requested string
    // TODO: this mechanism could perhaps also be used to set the arg0 for login shells, as below
    if let Some(arg0) = options.arg0 {
        command.arg0(arg0);
    }

    if options.is_login {
        // signal to the operating system that the command is a login shell by prefixing "-"
        let mut process_name = qualified_path
            .file_name()
            .map(|osstr| osstr.as_bytes().to_vec())
            .unwrap_or_default();
        process_name.insert(0, b'-');
        command.arg0(OsStr::from_bytes(&process_name));
    }

    if options.noexec {
        noexec::add_noexec_filter(&mut command);
    }

    // Decide if the pwd should be changed. `--chdir` takes precedence over `-i`.
    let path = options
        .chdir
        .map(|chdir| chdir.to_owned())
        .or_else(|| options.is_login.then(|| options.user.home.clone().into()))
        .clone();

    // set target user and groups
    set_target_user(&mut command, options.user.clone(), options.group.clone());

    // change current directory if necessary.
    if let Some(path) = path {
        let is_chdir = options.chdir.is_some();

        // SAFETY: Chdir as used internally by set_current_dir is async-signal-safe. The logger we
        // use is also async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                if let Err(err) = env::set_current_dir(&path) {
                    user_error!("unable to change directory to {}: {}", path.display(), err);
                    if is_chdir {
                        return Err(err);
                    }
                }

                Ok(())
            });
        }
    }

    let sudo_pid = ProcessId::new(std::process::id() as i32);

    if options.use_pty {
        match UserTerm::open() {
            Ok(user_tty) => exec_pty(sudo_pid, command, user_tty),
            Err(err) => {
                dev_info!("Could not open user's terminal, not allocating a pty: {err}");
                exec_no_pty(sudo_pid, command)
            }
        }
    } else {
        exec_no_pty(sudo_pid, command)
    }
}

/// Exit reason for the command executed by sudo.
#[derive(Debug)]
pub enum ExitReason {
    Code(i32),
    Signal(i32),
}

// Kill the process with increasing urgency.
//
// Based on `terminate_command`.
fn terminate_process(pid: ProcessId, use_killpg: bool) {
    let kill_fn = if use_killpg { killpg } else { kill };
    kill_fn(pid, SIGHUP).ok();
    kill_fn(pid, SIGTERM).ok();
    std::thread::sleep(Duration::from_secs(2));
    kill_fn(pid, SIGKILL).ok();
}

trait HandleSigchld: Process {
    const OPTIONS: WaitOptions;

    fn on_exit(&mut self, exit_code: c_int, registry: &mut EventRegistry<Self>);
    fn on_term(&mut self, signal: SignalNumber, registry: &mut EventRegistry<Self>);
    fn on_stop(&mut self, signal: SignalNumber, registry: &mut EventRegistry<Self>);
}

fn handle_sigchld<T: HandleSigchld>(
    handler: &mut T,
    registry: &mut EventRegistry<T>,
    child_name: &'static str,
    child_pid: ProcessId,
) {
    let status = loop {
        match child_pid.wait(T::OPTIONS) {
            Err(WaitError::Io(err)) if was_interrupted(&err) => {}
            // This only happens if we receive `SIGCHLD` but there's no status update from the
            // monitor.
            Err(WaitError::Io(err)) => {
                return dev_info!("cannot wait for {child_pid} ({child_name}): {err}");
            }
            // This only happens if the monitor exited and any process already waited for the
            // monitor.
            Err(WaitError::NotReady) => {
                return dev_info!("{child_pid} ({child_name}) has no status report");
            }
            Ok((_pid, status)) => break status,
        }
    };
    if let Some(exit_code) = status.exit_status() {
        dev_info!("{child_pid} ({child_name}) exited with status code {exit_code}");
        handler.on_exit(exit_code, registry)
    } else if let Some(signal) = status.stop_signal() {
        dev_info!(
            "{child_pid} ({child_name}) was stopped by {}",
            signal_fmt(signal),
        );
        handler.on_stop(signal, registry)
    } else if let Some(signal) = status.term_signal() {
        dev_info!(
            "{child_pid} ({child_name}) was terminated by {}",
            signal_fmt(signal),
        );
        handler.on_term(signal, registry)
    } else if status.did_continue() {
        dev_info!("{child_pid} ({child_name}) continued execution");
    } else {
        dev_warn!("unexpected wait status for {child_pid} ({child_name})")
    }
}

fn signal_fmt(signal: SignalNumber) -> Cow<'static, str> {
    match signal_name(signal) {
        name @ Cow::Owned(_) => match signal {
            SIGCONT_BG => "SIGCONT_BG".into(),
            SIGCONT_FG => "SIGCONT_FG".into(),
            _ => name,
        },
        name => name,
    }
}

const fn cond_fmt<'a>(cond: bool, true_s: &'a str, false_s: &'a str) -> &'a str {
    if cond {
        true_s
    } else {
        false_s
    }
}

const fn opt_fmt(cond: bool, s: &str) -> &str {
    cond_fmt(cond, s, "")
}
