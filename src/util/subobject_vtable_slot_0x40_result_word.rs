//! Offset-vtable-slot-0x40 result-word accessor.
//!
//! `subobject_vtable_slot_0x40_result_word` — original: `FUN_082a6784` @
//! **0x082a6784** (8 bytes; true extent `0x082a6784..0x082a678c`, with the
//! next independently entered tail branch at `0x082a678c`). Raw A32 decoding
//! finds three direct incoming calls, all unconditional plain `bl` (at
//! `0x08299a28`, `0x08299ad0`, and `0x08299b74`); there are no predicated
//! direct `bl` calls. The body adds eight bytes to its receiver, then tail
//! branches to `0x083d5f2c`, which calls that subobject's vtable slot `+0x40`
//! and returns the word addressed by its result.
//!
//! `0x083d5f2c` has no recovered semantic name, so this port reuses the
//! independently verified vtable-slot implementation rather than creating a
//! callee seam. Deliberate deviation: Rust performs a normal call instead of
//! the retail tail branch; the adjusted receiver and returned word are
//! unchanged.

use super::vtable_slot_0x40_result_word::vtable_slot_0x40_result_word;
#[cfg(test)]
use super::vtable_slot_0x40_result_word::{HostResultWordObject, HostResultWordVtable};

/// Calls the result-word vtable slot on the subobject at `receiver + 8`.
///
/// # Safety
///
/// `receiver.add(8)`, its vtable slot, and the pointer yielded by that slot
/// must be valid. retailOS performs no null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn subobject_vtable_slot_0x40_result_word(receiver: *mut u8) -> u32 {
    vtable_slot_0x40_result_word(receiver.add(8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVER: *mut u8 = ptr::null_mut();
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_result_word(object: *mut u8) -> *mut u32 {
        RECEIVER = object;
        ptr::addr_of_mut!(RESULT)
    }

    #[repr(C)]
    struct ReceiverWithSubobject {
        prefix: [u32; 2],
        subobject: HostResultWordObject,
    }

    #[test]
    fn dispatches_slot_40_on_the_subobject_at_offset_eight() {
        let _guard = TEST_LOCK.lock();
        let vtable = HostResultWordVtable {
            unresolved_00_to_3c: [0; 0x40 / 4],
            result_word: record_result_word,
        };
        let mut receiver = ReceiverWithSubobject {
            prefix: [0xa5a5_a5a5, 0x5a5a_5a5a],
            subobject: HostResultWordObject { vtable: &vtable },
        };
        unsafe {
            RESULT = 0xdead_beef;
            RECEIVER = ptr::null_mut();
            let receiver_ptr = ptr::addr_of_mut!(receiver).cast::<u8>();
            assert_eq!(subobject_vtable_slot_0x40_result_word(receiver_ptr), 0xdead_beef);
            assert_eq!(RECEIVER, receiver_ptr.add(8));
            assert_eq!(receiver.prefix, [0xa5a5_a5a5, 0x5a5a_5a5a]);
        }
    }

    #[test]
    fn returns_the_current_word_from_the_subobject_method() {
        let _guard = TEST_LOCK.lock();
        let vtable = HostResultWordVtable {
            unresolved_00_to_3c: [0; 0x40 / 4],
            result_word: record_result_word,
        };
        let mut receiver = ReceiverWithSubobject {
            prefix: [0; 2],
            subobject: HostResultWordObject { vtable: &vtable },
        };
        unsafe {
            let receiver_ptr = ptr::addr_of_mut!(receiver).cast::<u8>();
            RESULT = 0;
            assert_eq!(subobject_vtable_slot_0x40_result_word(receiver_ptr), 0);
            RESULT = u32::MAX;
            assert_eq!(subobject_vtable_slot_0x40_result_word(receiver_ptr), u32::MAX);
        }
    }
}
