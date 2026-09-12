//! `payload_list_owner_destroy` — retailOS `FUN_081fc930` @ `0x081fc930`.
//!
//! Raw ARM is exactly 144 bytes (36 words), from `0x081fc930` through the
//! closing `pop {r1,r2,r3,r4,r5,pc}` at `0x081fc9bc`; `0x081fc9c0` starts a
//! distinct constructor. Decoding every ARM B/BL immediate in `osos.dec`
//! finds eight inbound direct call sites, all unconditional `bl` (no
//! predicated forms): `0x0814c770`, `0x081682a8`, `0x081f0104`, `0x082086d4`,
//! `0x08236248`, `0x08262bb8`, `0x0828c1c8`, and `0x083b5328`.
//!
//! The object has a required payload target pointer at word +1, a circular
//! list sentinel at +8, its list count at +0x18, and a POSIX mutex at +0x24.
//! It locks the mutex, panics fatally for a NULL payload, conditionally hands
//! `(payload, list)` to the unresolved `FUN_0818ad44`, clears the payload
//! word, unlocks and destroys the mutex, then erases list nodes until the
//! sentinel through unresolved `FUN_083d5c90`. It returns `this`.
//!
//! Deliberate deviations: neither direct callee has an established identity,
//! so they remain explicit dispatch boundaries rather than receiving invented
//! names. The lock, unlock, fatal path, and mutex destructor use their
//! existing Rust ports; the two unresolved calls are `blx` slots instead of
//! the retailOS direct `bl` instructions.

use crate::heap::veneers::heap_panic;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};
use super::mutex_destroy::cxx_mutex_destroy;

const PAYLOAD_WORD: usize = 1;
const LIST_OFFSET: usize = 0x08;
const LIST_HEAD_WORD: usize = 1;
const LIST_COUNT_WORD: usize = 6;
const MUTEX_OFFSET: usize = 0x24;

/// Direct-callee boundary for the two unresolved calls in
/// [`payload_list_owner_destroy`].
#[derive(Clone, Copy)]
pub struct PayloadListOwnerDestroyOps {
    /// `FUN_0818ad44(payload, list)`: its identity has not been established.
    pub teardown_payload_list: unsafe extern "C" fn(payload: *mut u8, list: *mut u8),
    /// `FUN_083d5c90(out, list, cursor)`: erases one list cursor and returns
    /// the next cursor through `out`; its identity has not been established.
    pub erase_list_cursor: unsafe extern "C" fn(out: *mut u32, list: *mut u8, cursor: *mut u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_teardown_payload_list(payload: *mut u8, list: *mut u8) {
    let teardown: unsafe extern "C" fn(*mut u8, *mut u8) =
        unsafe { core::mem::transmute(0x0818_ad44usize) };
    unsafe { teardown(payload, list) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_erase_list_cursor(out: *mut u32, list: *mut u8, cursor: *mut u32) {
    let erase: unsafe extern "C" fn(*mut u32, *mut u8, *mut u32) =
        unsafe { core::mem::transmute(0x083d_5c90usize) };
    unsafe { erase(out, list, cursor) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_teardown_payload_list(_payload: *mut u8, _list: *mut u8) {
    panic!("payload_list_owner_destroy requires unresolved FUN_0818ad44")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_erase_list_cursor(_out: *mut u32, _list: *mut u8, _cursor: *mut u32) {
    panic!("payload_list_owner_destroy requires unresolved FUN_083d5c90")
}

#[cfg(target_os = "none")]
pub const DEFAULT_PAYLOAD_LIST_OWNER_DESTROY_OPS: PayloadListOwnerDestroyOps = PayloadListOwnerDestroyOps {
    teardown_payload_list: firmware_teardown_payload_list,
    erase_list_cursor: firmware_erase_list_cursor,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_PAYLOAD_LIST_OWNER_DESTROY_OPS: PayloadListOwnerDestroyOps = PayloadListOwnerDestroyOps {
    teardown_payload_list: missing_teardown_payload_list,
    erase_list_cursor: missing_erase_list_cursor,
};

/// Active unresolved direct-callee boundary. Host tests install recorders.
pub static mut PAYLOAD_LIST_OWNER_DESTROY_OPS: PayloadListOwnerDestroyOps =
    DEFAULT_PAYLOAD_LIST_OWNER_DESTROY_OPS;

#[inline(always)]
unsafe fn destroy_ops() -> PayloadListOwnerDestroyOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PAYLOAD_LIST_OWNER_DESTROY_OPS)) }
}

#[inline(always)]
unsafe fn read_word(base: *mut u8, word: usize) -> u32 {
    unsafe { base.cast::<u32>().add(word).read() }
}

#[inline(always)]
unsafe fn write_word(base: *mut u8, word: usize, value: u32) {
    unsafe { base.cast::<u32>().add(word).write(value) }
}

/// Destroys the mutex-protected payload/list owner at `this` and returns it.
///
/// # Safety
/// `this` must address the observed target-word layout. Its payload, list,
/// and mutex fields must be valid for every operation their selected paths
/// reach. The unresolved callbacks must honor the direct-call ABI above.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.payload_list_owner_destroy")]
#[inline(never)]
pub unsafe extern "C" fn payload_list_owner_destroy(this: *mut u8) -> *mut u8 {
    let mutex = unsafe { this.add(MUTEX_OFFSET) };
    unsafe { posix_mutex_lock(mutex.cast::<PosixMutex>()) };

    let payload = unsafe { read_word(this, PAYLOAD_WORD) as usize as *mut u8 };
    if payload.is_null() {
        unsafe { heap_panic() };
    }

    let list = unsafe { this.add(LIST_OFFSET) };
    if unsafe { read_word(this, LIST_COUNT_WORD) } != 0 {
        let ops = unsafe { destroy_ops() };
        unsafe { (ops.teardown_payload_list)(payload, list) };
    }
    unsafe { write_word(this, PAYLOAD_WORD, 0) };

    unsafe { posix_mutex_unlock(mutex.cast::<PosixMutex>()) };
    unsafe { cxx_mutex_destroy(mutex) };

    if unsafe { read_word(this, LIST_COUNT_WORD) } != 0 {
        let mut cursor = unsafe { read_word(list, LIST_HEAD_WORD) };
        let sentinel = list as usize as u32;
        loop {
            if cursor == sentinel {
                break;
            }
            let mut next = 0;
            let ops = unsafe { destroy_ops() };
            unsafe { (ops.erase_list_cursor)(&mut next, list, &mut cursor) };
            cursor = next;
        }
    }

    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;
    use std::vec::Vec;
    use std::vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: Option<Vec<Event>> = None;

    #[derive(Debug, Eq, PartialEq)]
    enum Event {
        Teardown { payload: usize, list: usize },
        Erase { list: usize, cursor: u32 },
    }

    unsafe extern "C" fn recording_teardown(payload: *mut u8, list: *mut u8) {
        unsafe {
            EVENTS.as_mut().unwrap().push(Event::Teardown {
                payload: payload as usize,
                list: list as usize,
            });
        }
    }

    unsafe extern "C" fn erase_to_sentinel(out: *mut u32, list: *mut u8, cursor: *mut u32) {
        unsafe {
            EVENTS.as_mut().unwrap().push(Event::Erase {
                list: list as usize,
                cursor: cursor.read(),
            });
            out.write(list as usize as u32);
        }
    }

    const RECORDING_OPS: PayloadListOwnerDestroyOps = PayloadListOwnerDestroyOps {
        teardown_payload_list: recording_teardown,
        erase_list_cursor: erase_to_sentinel,
    };

    unsafe fn zeroed_owner(base: *mut u8, payload: *mut u8, count: u32, head: u32) {
        unsafe {
            ptr::write_bytes(base, 0, 0x60);
            write_word(base, PAYLOAD_WORD, payload as usize as u32);
            write_word(base, LIST_COUNT_WORD, count);
            write_word(base.add(LIST_OFFSET), LIST_HEAD_WORD, head);
        }
    }

    #[test]
    fn empty_list_skips_callbacks_and_nonempty_list_tears_down_then_erases() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::PAYLOAD_LIST_OWNER_DESTROY, 0x400) else {
            return;
        };
        let empty = slab;
        let populated = unsafe { slab.add(0x100) };
        let payload = unsafe { slab.add(0x200) };
        let node = unsafe { slab.add(0x280) };

        unsafe {
            EVENTS = Some(Vec::new());
            PAYLOAD_LIST_OWNER_DESTROY_OPS = RECORDING_OPS;
            zeroed_owner(empty, empty, 0, empty.add(LIST_OFFSET) as usize as u32);
            assert_eq!(payload_list_owner_destroy(empty), empty);
            assert_eq!(read_word(empty, PAYLOAD_WORD), 0);
            assert!(EVENTS.as_ref().unwrap().is_empty());

            zeroed_owner(populated, payload, 1, node as usize as u32);
            assert_eq!(payload_list_owner_destroy(populated), populated);
            assert_eq!(read_word(populated, PAYLOAD_WORD), 0);
            assert_eq!(
                EVENTS.as_ref().unwrap(),
                &vec![
                    Event::Teardown { payload: payload as usize, list: populated.add(LIST_OFFSET) as usize },
                    Event::Erase { list: populated.add(LIST_OFFSET) as usize, cursor: node as usize as u32 },
                ],
            );
            PAYLOAD_LIST_OWNER_DESTROY_OPS = DEFAULT_PAYLOAD_LIST_OWNER_DESTROY_OPS;
            EVENTS = None;
        }
    }
}
