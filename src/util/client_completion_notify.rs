//! `client_completion_notify` — original: `FUN_081fbf1c` @ `0x081fbf1c`
//! (76 bytes; 1 plain `bl` and 1 predicated `bl`).
//!
//! Tests the client's `0x10000` state flag, then accepts completion when the
//! unsigned produced counter at `+0x18` is no greater than expected at
//! `+0x1c`. On success it optionally notifies the parent word at `+0x04` with
//! event code 5 and the client pointer, and returns 1; every other path
//! returns 0. The parent notification body at `0x0818a41c` is unported, so it
//! is an ops-table boundary: the target default deliberately suppresses that
//! unavailable external side effect, while host tests install a recorder.

use crate::util::state_flags::state_flags_contain;

const PARENT: usize = 0x04;
const PRODUCED: usize = 0x18;
const EXPECTED: usize = 0x1c;
const COMPLETION_FLAG: u32 = 0x10000;
const COMPLETION_EVENT: u32 = 5;

/// Boundary for the unported parent notification @ `0x0818a41c`.
#[derive(Clone, Copy)]
pub struct ClientCompletionNotifyOps {
    pub notify_parent: unsafe extern "C" fn(parent: u32, event: u32, client: *mut u8),
}

unsafe extern "C" fn suppress_parent_notification(_parent: u32, _event: u32, _client: *mut u8) {}

/// Wired default until the parent notification body is ported.
pub const DEFAULT_CLIENT_COMPLETION_NOTIFY_OPS: ClientCompletionNotifyOps = ClientCompletionNotifyOps {
    notify_parent: suppress_parent_notification,
};

/// Active notification boundary. Host tests replace it with a recorder.
pub static mut CLIENT_COMPLETION_NOTIFY_OPS: ClientCompletionNotifyOps = DEFAULT_CLIENT_COMPLETION_NOTIFY_OPS;

#[inline(always)]
unsafe fn word(client: *mut u8, offset: usize) -> u32 {
    (client.add(offset) as *const u32).read_volatile()
}

/// Tests whether a client completed its current work and optionally tells its
/// parent. `notify_parent != 0` preserves the original predicated call.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn client_completion_notify(client: *mut u8, notify_parent: u32) -> u32 {
    if state_flags_contain(client, COMPLETION_FLAG) == 0 || word(client, PRODUCED) > word(client, EXPECTED) {
        return 0;
    }

    if notify_parent != 0 {
        let notify = core::ptr::read_volatile(core::ptr::addr_of!(CLIENT_COMPLETION_NOTIFY_OPS.notify_parent));
        notify(word(client, PARENT), COMPLETION_EVENT, client);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use parking_lot::{Mutex, MutexGuard};
    use super::*;
    use core::ptr::{addr_of_mut, write_volatile};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: Option<(u32, u32, usize)> = None;

    #[repr(align(4))]
    struct Client([u8; 0x50]);

    unsafe extern "C" fn record(parent: u32, event: u32, client: *mut u8) {
        CALL = Some((parent, event, client as usize));
    }

    unsafe fn set_word(client: *mut u8, offset: usize, value: u32) {
        write_volatile(client.add(offset) as *mut u32, value);
    }

    unsafe fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock();
        CALL = None;
        addr_of_mut!(CLIENT_COMPLETION_NOTIFY_OPS).write(ClientCompletionNotifyOps { notify_parent: record });
        guard
    }

    unsafe fn restore(guard: MutexGuard<'static, ()>) {
        addr_of_mut!(CLIENT_COMPLETION_NOTIFY_OPS).write(DEFAULT_CLIENT_COMPLETION_NOTIFY_OPS);
        drop(guard);
    }

    #[test]
    fn notifies_only_for_flagged_completed_client() {
        unsafe {
            let guard = install();
            let mut client = Client([0; 0x50]);
            let pointer = client.0.as_mut_ptr();
            set_word(pointer, PARENT, 0x1234_5678);
            set_word(pointer, 0x44, COMPLETION_FLAG);
            set_word(pointer, PRODUCED, 9);
            set_word(pointer, EXPECTED, 9);

            assert_eq!(client_completion_notify(pointer, 1), 1);
            assert_eq!(CALL, Some((0x1234_5678, COMPLETION_EVENT, pointer as usize)));
            restore(guard);
        }
    }

    #[test]
    fn rejects_missing_flag_or_counter_overflow_without_notification() {
        unsafe {
            let guard = install();
            let mut client = Client([0; 0x50]);
            let pointer = client.0.as_mut_ptr();
            set_word(pointer, PRODUCED, 0);
            set_word(pointer, EXPECTED, u32::MAX);
            assert_eq!(client_completion_notify(pointer, 1), 0);
            assert_eq!(CALL, None);

            set_word(pointer, 0x44, COMPLETION_FLAG);
            set_word(pointer, PRODUCED, u32::MAX);
            set_word(pointer, EXPECTED, 0);
            assert_eq!(client_completion_notify(pointer, 1), 0);
            assert_eq!(CALL, None);
            restore(guard);
        }
    }

    #[test]
    fn completed_client_can_skip_notification() {
        unsafe {
            let guard = install();
            let mut client = Client([0; 0x50]);
            let pointer = client.0.as_mut_ptr();
            set_word(pointer, 0x44, COMPLETION_FLAG);
            set_word(pointer, PRODUCED, 0);
            set_word(pointer, EXPECTED, 1);

            assert_eq!(client_completion_notify(pointer, 0), 1);
            assert_eq!(CALL, None);
            restore(guard);
        }
    }
}
