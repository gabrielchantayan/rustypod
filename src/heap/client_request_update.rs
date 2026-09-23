//! Port of the block-manager client's synchronized request update.
//!
//! `client_request_update` — original: `FUN_081fbed0` @ **0x081fbed0**
//! (**76 bytes**, `0x081fbed0..0x081fbf1c`). Raw ARM decoding finds **one
//! plain `bl`** (the mutex-lock veneer @ `0x082621a8`) and **one predicated
//! `blne`** (manager event notification @ `0x0818a3b4`); the final branch is
//! the mutex-unlock veneer @ `0x082621ac`, not part of another function.
//!
//! Under the client's POSIX mutex at `+0x24`, the routine compares the current
//! request byte limit (`+0x48`) and kind (`+0x40`) with its inputs. A changed
//! pair is stored and notifies the parent manager (`+0x04`) with event 10.
//! It always releases the mutex. Deliberate deviation: the retail tail branch
//! to the unlock veneer is a normal call to the already ported mutex helper.

use crate::heap::manager_notification::manager_event_notify;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

const CLIENT_MUTEX_OFFSET: usize = 0x24;
const CLIENT_MANAGER_OFFSET: usize = 0x04;
const REQUEST_KIND_OFFSET: usize = 0x40;
const REQUEST_BYTE_LIMIT_OFFSET: usize = 0x48;
const REQUEST_CHANGED_EVENT: u32 = 10;

/// Updates a block-manager client's request parameters and reports a change.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn client_request_update(
    client: *mut u8,
    byte_limit: u32,
    request_kind: u32,
) {
    let mutex = client.add(CLIENT_MUTEX_OFFSET).cast::<PosixMutex>();
    posix_mutex_lock(mutex);

    let stored_byte_limit = client.add(REQUEST_BYTE_LIMIT_OFFSET).cast::<u32>().read();
    let stored_request_kind = client.add(REQUEST_KIND_OFFSET).cast::<u32>().read();
    if stored_byte_limit != byte_limit || stored_request_kind != request_kind {
        client.add(REQUEST_BYTE_LIMIT_OFFSET).cast::<u32>().write(byte_limit);
        client.add(REQUEST_KIND_OFFSET).cast::<u32>().write(request_kind);
        let manager = client.add(CLIENT_MANAGER_OFFSET).cast::<u32>().read() as usize as *mut u8;
        manager_event_notify(manager, REQUEST_CHANGED_EVENT);
    }

    posix_mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::manager_notification::{
        ManagerNotificationOps, DEFAULT_MANAGER_NOTIFICATION_OPS, MANAGER_NOTIFICATION_OPS,
    };
    use crate::heap::veneers::{HeapVeneerOps, DEFAULT_HEAP_OPS, HEAP_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut NODE: [u8; 12] = [0; 12];
    static mut EVENT: u32 = 0;
    static mut QUEUE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn alloc(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        assert_eq!((size, tag), (12, 2));
        core::ptr::addr_of_mut!(NODE).cast()
    }

    unsafe extern "C" fn construct(node: *mut u8, event: u32) -> *mut u8 {
        EVENT = event;
        node
    }

    unsafe extern "C" fn enqueue(queue: *mut u8, _node: *mut u8) -> i32 {
        QUEUE = queue;
        0
    }

    #[test]
    fn stores_changed_pair_and_notifies_once() {
        let _guard = LOCK.lock();
        unsafe {
            let old_heap: HeapVeneerOps = HEAP_OPS;
            let old_notification = MANAGER_NOTIFICATION_OPS;
            let mut heap = DEFAULT_HEAP_OPS;
            heap.alloc = alloc;
            HEAP_OPS = heap;
            MANAGER_NOTIFICATION_OPS = ManagerNotificationOps {
                construct_event_node: construct,
                enqueue_event_node: enqueue,
            };

            let Some(client) = try_map_u32_slab(hints::CLIENT_REQUEST_UPDATE, 0x1000) else {
                assert!(note_missing_u32_fixture("heap/client_request_update"));
                return;
            };
            client.write_bytes(0, 0x1000);
            let manager = client.add(0x100);
            client.add(CLIENT_MANAGER_OFFSET).cast::<u32>().write(manager as usize as u32);
            client.add(REQUEST_KIND_OFFSET).cast::<u32>().write(3);
            client.add(REQUEST_BYTE_LIMIT_OFFSET).cast::<u32>().write(64);
            client_request_update(client, 128, 5);
            assert_eq!(
                (
                    client.add(REQUEST_KIND_OFFSET).cast::<u32>().read(),
                    client.add(REQUEST_BYTE_LIMIT_OFFSET).cast::<u32>().read(),
                ),
                (5, 128)
            );
            assert_eq!(EVENT, REQUEST_CHANGED_EVENT);
            assert_eq!(QUEUE, manager.add(0x3c));

            EVENT = 0;
            QUEUE = core::ptr::null_mut();
            client_request_update(client, 128, 5);
            assert_eq!(EVENT, 0, "unchanged parameters must not notify");
            assert!(QUEUE.is_null());

            HEAP_OPS = old_heap;
            MANAGER_NOTIFICATION_OPS = old_notification;
        }
    }
}
