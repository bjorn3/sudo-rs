use std::{
    fmt::Debug,
    io,
    os::fd::{AsFd, AsRawFd, RawFd},
};

use libc::{c_short, pollfd, POLLIN, POLLOUT};

use crate::{cutils::cerr, log::dev_debug};

pub(super) trait Process: Sized {
    /// IO Events that this process should handle.
    type Event: Copy + Debug;
    /// Reason why the event loop should break.
    type Break;
    /// Reason why the event loop should exit.
    type Exit;
    /// Handle the corresponding event.
    fn on_event(
        &mut self,
        event: Self::Event,
        registry: &mut EventRegistry<Self>,
    ) -> Result<(), StopReason<Self>>;
}

pub(super) enum StopReason<T: Process> {
    Break(T::Break),
    Exit(T::Exit),
}

#[derive(PartialEq, Eq, Hash, Ord, PartialOrd, Clone, Copy)]
struct EventId(usize);

pub(super) struct EventHandle {
    id: EventId,
    should_poll: bool,
}

impl EventHandle {
    /// Ignore the event associated with this handle, meaning that the file descriptor for this
    /// event will not be polled anymore for that specific event.
    pub(super) fn ignore<T: Process>(&mut self, registry: &mut EventRegistry<T>) {
        if self.should_poll {
            if let Some(poll_fd) = registry.poll_fds.get_mut(self.id.0) {
                poll_fd.should_poll = false;
                self.should_poll = false;
            }
        }
    }

    /// Stop ignoring the event associated with this handle, meaning that the file descriptor for
    /// this event will be polled for that specific event.
    pub(super) fn resume<T: Process>(&mut self, registry: &mut EventRegistry<T>) {
        if !self.should_poll {
            if let Some(poll_fd) = registry.poll_fds.get_mut(self.id.0) {
                poll_fd.should_poll = true;
                self.should_poll = true;
            }
        }
    }
}

/// The kind of event that will be monitored for a file descriptor.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PollEvent {
    /// Data may be read without blocking.
    Readable,
    /// Data may be written without blocking.
    Writable,
}

struct PollFd<T: Process> {
    // FIXME ensure that the fd is not closed while the event registry is still open
    raw_fd: RawFd,
    event_flags: c_short,
    should_poll: bool,
    event: T::Event,
}

/// A type able to register file descriptors to be polled.
pub(super) struct EventRegistry<T: Process> {
    poll_fds: Vec<PollFd<T>>,
}

impl<T: Process> EventRegistry<T> {
    /// Create a new and empty registry..
    pub(super) const fn new() -> Self {
        Self {
            poll_fds: Vec::new(),
        }
    }

    /// Set the `fd` descriptor to be polled for `poll_event` events and produce `event` when `fd` is
    /// ready.
    pub(super) fn register_event<F: AsFd>(
        &mut self,
        fd: &F,
        poll_event: PollEvent,
        event_fn: impl Fn(PollEvent) -> T::Event,
    ) -> EventHandle {
        let id = EventId(self.poll_fds.len());

        self.poll_fds.push(PollFd {
            raw_fd: fd.as_fd().as_raw_fd(),
            event_flags: match poll_event {
                PollEvent::Readable => POLLIN,
                PollEvent::Writable => POLLOUT,
            },
            should_poll: true,
            event: event_fn(poll_event),
        });

        EventHandle {
            id,
            should_poll: true,
        }
    }

    /// Poll the file descriptors of that are not being ignored and return the ID of the
    /// descriptors that are ready to be read or written.
    ///
    /// Calling this function will block until one of the file descriptors in the set is ready.
    fn poll(&mut self) -> io::Result<Vec<EventId>> {
        let (mut ids, mut fds): (Vec<EventId>, Vec<pollfd>) = self
            .poll_fds
            .iter()
            .enumerate()
            .filter_map(|(index, poll_fd)| {
                poll_fd.should_poll.then_some({
                    (
                        EventId(index),
                        pollfd {
                            fd: poll_fd.raw_fd,
                            events: poll_fd.event_flags,
                            revents: 0,
                        },
                    )
                })
            })
            .unzip();

        // Don't call poll if there are no file descriptors to be polled.
        if ids.is_empty() {
            return Ok(ids);
        }

        // SAFETY: `poll` expects a pointer to an array of file descriptors (first argument),
        // the length of which is indicated by the second argument; the third argument being -1
        // denotes an infinite timeout.
        // FIXME: we should set either a timeout or use ppoll when available.
        cerr(unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) })?;

        // Remove the ids that correspond to file descriptors that were not ready.
        for (i, fd) in fds.iter().enumerate().rev() {
            let events = fd.events & fd.revents;
            if !((events & POLLIN != 0) || (events & POLLOUT != 0)) {
                ids.remove(i);
            }
        }

        Ok(ids)
    }

    /// Run the event loop over this registry using `process` to handle the produced events.
    ///
    /// The event loop will continue indefinitely unless you return `Err` from [`Process::on_event`].
    #[track_caller]
    pub(super) fn event_loop(mut self, process: &mut T) -> StopReason<T> {
        let mut event_queue = Vec::with_capacity(self.poll_fds.len());

        loop {
            // FIXME: maybe we should return the IO error instead.
            if let Ok(ids) = self.poll() {
                for EventId(index) in ids {
                    let event = self.poll_fds[index].event;
                    dev_debug!("event {event:?} is ready");
                    event_queue.push(event);
                }

                for event in event_queue.drain(..) {
                    if let Err(reason) = process.on_event(event, &mut self) {
                        return reason;
                    }
                }
            }
        }
    }
}
