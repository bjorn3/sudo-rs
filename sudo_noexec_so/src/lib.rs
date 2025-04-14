// On Linux we can use a seccomp() filter to disable exec.

#[cfg(not(target_os = "linux"))]
compile_error!("sudo_noexec shouldn't be compiled for non-Linux systems");

use std::cmp;
use std::mem::offset_of;
use std::ptr::addr_of;

use libc::{
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JUMP, BPF_K, BPF_LD, BPF_RET, BPF_STMT, PR_SET_NO_NEW_PRIVS,
    SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_GET_NOTIF_SIZES, SECCOMP_RET_ALLOW,
    SECCOMP_SET_MODE_FILTER, SECCOMP_USER_NOTIF_FLAG_CONTINUE, SYS_execve, SYS_execveat,
    SYS_seccomp, c_int, c_uint, c_ulong, calloc, close, fork, ioctl, prctl, seccomp_data,
    seccomp_notif, seccomp_notif_resp, seccomp_notif_sizes, sock_filter, sock_fprog, syscall,
};

const SECCOMP_RET_USER_NOTIF: c_uint = 0x7fc00000;
const SECCOMP_IOCTL_NOTIF_RECV: c_ulong = 0xc0502100;
const SECCOMP_IOCTL_NOTIF_SEND: c_ulong = 0xc0182101;

unsafe fn seccomp<T>(operation: c_uint, flags: c_uint, args: *mut T) -> c_int {
    unsafe { syscall(SYS_seccomp, operation, flags, args) as c_int }
}

#[used]
#[unsafe(link_section = ".init_array")]
static NOEXEC_CTOR: extern "C" fn() = noexec_ctor;

extern "C" fn noexec_ctor() {
    // SAFETY: libc unnecessarily marks these functions as unsafe
    let exec_filter: [sock_filter; 5] = unsafe {
        [
            // Load syscall number into the accumulator
            BPF_STMT((BPF_LD | BPF_ABS) as _, offset_of!(seccomp_data, nr) as _),
            // Jump to user notify for execve/execveat
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as _, SYS_execve as _, 2, 0),
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as _, SYS_execveat as _, 1, 0),
            // Allow non-matching syscalls
            BPF_STMT((BPF_RET | BPF_K) as _, SECCOMP_RET_ALLOW),
            // Notify sudo about execve/execveat syscall
            BPF_STMT((BPF_RET | BPF_K) as _, SECCOMP_RET_USER_NOTIF as _),
        ]
    };

    let exec_fprog = sock_fprog {
        len: 5,
        filter: addr_of!(exec_filter) as *mut sock_filter,
    };

    // SAFETY: The first prctl is trivially safe as it doesn't touch any memory
    // and the second prctl passes a valid sock_fprog as argument.
    unsafe {
        // SECCOMP_SET_MODE_FILTER will fail unless the process has
        // CAP_SYS_ADMIN or the no_new_privs bit is set.
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 {
            // While the man page warns againt using seccomp_unotify as security
            // mechanism, the TOCTOU problem that is described there isn't
            // relevant here. We only SECCOMP_USER_NOTIF_FLAG_CONTINUE the first
            // execve which is done by ourself and thus trusted.
            // FIXME handle error
            let notify_fd = seccomp(
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER as _,
                &exec_fprog as *const sock_fprog as *mut sock_fprog,
            );
            if fork() == 0 {
                close(notify_fd);
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
        }
    }
}
