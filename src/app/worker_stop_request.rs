//! Worker stop request — `FUN_08132cc8` at load address `0x08132cc8`.
//! True extent: 48 bytes, ending at the next push at `0x08132cf8`.
//! Raw firmware scan: two incoming BL sites (one plain, one BLNE), two
//! outgoing plain BLs and one tail B. Acquire counted mutex +0x74, publish
//! cancellation byte +0x64, release it, publish notification byte +0x66,
//! then post mailbox slot +0x70. The worker checks +0x64 to abandon work;
//! the stop-and-wait caller polls the busy/cancellation state afterwards.
//! Deviations: repr(C) pointer fields expand on the host; firmware offsets
//! remain exact on ARM. Existing Rust mutex/mailbox ports replace all calls.

use core::ptr::addr_of_mut;
use crate::kernel::kobj::{mailbox_slot_post, Mailbox};
use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted, CountedMutex};

/// Prefix of the worker object through its counted mutex.
#[repr(C)]
pub struct WorkerStopState {
    pub prefix: [u8; 0x64],
    pub cancellation_requested: u8,
    pub reserved_65: u8,
    pub notification_pending: u8,
    pub reserved_67_6f: [u8; 9],
    pub mailbox: *mut Mailbox,
    pub lock: CountedMutex,
}

/// Requests cancellation and wakes the worker on every invocation.
///
/// # Safety
/// `worker` must be a live, exclusively accessible worker prefix with a valid
/// mailbox and initialized counted mutex. Neither pointer is NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn worker_stop_request(worker: *mut WorkerStopState) {
    let lock = addr_of_mut!((*worker).lock);
    mutex_lock_counted(lock);
    addr_of_mut!((*worker).cancellation_requested).write(1);
    mutex_unlock_counted(lock);
    addr_of_mut!((*worker).notification_pending).write(1);
    mailbox_slot_post(addr_of_mut!((*worker).mailbox));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync_mutex::Mutex;

    #[test]
    fn publishes_flags_preserves_neighbors_and_posts_each_request_with_wrapping_counts() {
        let _guard = crate::kernel::kobj::tests::HOOKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for initial in [0u32, 17, i32::MAX as u32, u32::MAX - 1] {
            let mut mailbox = Mailbox { state: initial, id: 0x1234 };
            let mut worker = WorkerStopState {
                prefix: [0xa5; 0x64], cancellation_requested: 0xff,
                reserved_65: 0x5a, notification_pending: 0,
                reserved_67_6f: [0x7b; 9], mailbox: &mut mailbox,
                lock: CountedMutex { mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0xabcdef }, hold_count: u32::MAX },
            };
            unsafe { worker_stop_request(&mut worker); }
            assert_eq!(worker.cancellation_requested, 1);
            assert_eq!(worker.notification_pending, 1);
            assert_eq!(mailbox.state, initial.wrapping_add(1));
            assert_eq!(worker.lock.hold_count, u32::MAX);
            assert_eq!(worker.prefix, [0xa5; 0x64]);
            assert_eq!(worker.reserved_65, 0x5a);
            assert_eq!(worker.reserved_67_6f, [0x7b; 9]);
            assert_eq!(worker.lock.mutex.unused, 0xabcdef);
            assert_eq!(mailbox.id, 0x1234);
            // Repeated requests still post, even when both flags are already set.
            if initial != u32::MAX - 1 {
                unsafe { worker_stop_request(&mut worker); }
                assert_eq!(mailbox.state, initial.wrapping_add(2));
            }
        }
    }
}
