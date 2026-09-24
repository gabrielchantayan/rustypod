//! Removes registered listeners matching a two-word key — original:
//! `FUN_0811f1a4` at load address `0x0811f1a4`.
//!
//! Raw `osos.dec` establishes the exact 160-byte extent: 40 words from
//! `push {r4-r6,lr}` at `0x0811f1a4` through `pop {r4-r6,pc}` at
//! `0x0811f23c`, followed by the `0x0898ce24` literal and the next function
//! at `0x0811f244`. The body has two plain `bl` calls (to
//! `not_equal_deref_alias_6f40` @ `0x083d6f40` and the pair predicate @
//! `0x082012c4`) and one predicated `blne` call (to list erase @
//! `0x083dc3fc`).
//!
//! If `owner+0x2c` is nonzero, it walks the circular listener list rooted at
//! `owner+0x28`. Each node's three-word payload starts at `node+8`; its tag is
//! `0x0898ce24`, and the remaining two words are compared against the supplied
//! key. Matching nodes are erased while iteration continues at the successor.
//!
//! Deliberate deviations: the unported pair predicate and list erase remain
//! fixed-address volatile seams on target and host-replaceable recorders.

use crate::cxx::templates::not_equal_deref;

const LIST_OFFSET: usize = 0x18;
const LIST_SENTINEL_OFFSET: usize = 0x10;
const LIST_ACTIVE_OFFSET: usize = 0x2c;
const LIST_HEAD_OFFSET: usize = 0x28;
const NODE_PAYLOAD_WORD_OFFSET: usize = 2;
const LISTENER_KEY_TAG: u32 = 0x0898_ce24;

type PairMatches = unsafe extern "C" fn(*const *const u32, *const u32) -> u32;
type ListErase = unsafe extern "C" fn(*mut u32, *mut u8, *const u32);

#[derive(Clone, Copy)]
pub struct RegisteredListenerRemoveOps {
    pub pair_matches: PairMatches,
    pub erase: ListErase,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_pair_matches(key: *const *const u32, candidate: *const u32) -> u32 {
    let predicate: PairMatches = unsafe { core::mem::transmute(0x0820_12c4usize) };
    unsafe { predicate(key, candidate) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_list_erase(out: *mut u32, list: *mut u8, cursor: *const u32) {
    let erase: ListErase = unsafe { core::mem::transmute(0x083d_c3fcusize) };
    unsafe { erase(out, list, cursor) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pair_matches(_key: *const *const u32, _candidate: *const u32) -> u32 {
    panic!("registered_listener_remove_by_pair requires pair predicate 0x082012c4")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_list_erase(_out: *mut u32, _list: *mut u8, _cursor: *const u32) {
    panic!("registered_listener_remove_by_pair requires list erase 0x083dc3fc")
}

#[cfg(target_os = "none")]
pub const DEFAULT_REGISTERED_LISTENER_REMOVE_OPS: RegisteredListenerRemoveOps = RegisteredListenerRemoveOps {
    pair_matches: firmware_pair_matches,
    erase: firmware_list_erase,
};
#[cfg(not(target_os = "none"))]
pub const DEFAULT_REGISTERED_LISTENER_REMOVE_OPS: RegisteredListenerRemoveOps = RegisteredListenerRemoveOps {
    pair_matches: missing_pair_matches,
    erase: missing_list_erase,
};

pub static mut REGISTERED_LISTENER_REMOVE_OPS: RegisteredListenerRemoveOps =
    DEFAULT_REGISTERED_LISTENER_REMOVE_OPS;

#[inline(always)]
fn remove_ops() -> RegisteredListenerRemoveOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGISTERED_LISTENER_REMOVE_OPS)) }
}

/// Removes every active listener whose payload pair is `(key_first, key_second)`.
///
/// # Safety
///
/// `owner` must point to the retail listener-owner layout. If active, its list
/// head and every linked node must be valid target-width pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_listener_remove_by_pair(
    owner: *mut u8,
    key_first: u32,
    key_second: u32,
) {
    if unsafe { owner.add(LIST_ACTIVE_OFFSET).cast::<u32>().read() } == 0 {
        return;
    }

    let list = unsafe { owner.add(LIST_OFFSET) };
    let sentinel = unsafe { owner.add(LIST_HEAD_OFFSET).cast::<u32>().read() };
    let mut key = [LISTENER_KEY_TAG, key_second, key_first];
    let key_pointer = key.as_mut_ptr() as *const u32;
    let mut cursor = unsafe { (sentinel as usize as *const u32).read() };
    let ops = remove_ops();

    while unsafe { not_equal_deref(&cursor, &sentinel) } != 0 {
        let current = cursor;
        if unsafe { (ops.pair_matches)(&key_pointer, (current as usize as *const u32).add(NODE_PAYLOAD_WORD_OFFSET)) } != 0 {
            unsafe { (ops.erase)(&mut cursor, list, &current) };
        } else {
            cursor = unsafe { (current as usize as *const u32).read() };
        }
    }
}

#[cfg(test)]
pub(crate) static REGISTERED_LISTENER_REMOVE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut PREDICATE_CALLS: usize = 0;
    static mut ERASE_CALLS: usize = 0;

    unsafe extern "C" fn record_pair_matches(key: *const *const u32, candidate: *const u32) -> u32 {
        unsafe {
            PREDICATE_CALLS += 1;
            let key = *key;
            u32::from(key.add(1).read() == candidate.add(1).read() && key.add(2).read() == candidate.add(2).read())
        }
    }

    unsafe extern "C" fn record_erase(out: *mut u32, _list: *mut u8, cursor: *const u32) {
        unsafe {
            ERASE_CALLS += 1;
            out.write((cursor.read() as usize as *const u32).read());
        }
    }

    struct OpsReset(RegisteredListenerRemoveOps);
    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(REGISTERED_LISTENER_REMOVE_OPS), self.0) }
        }
    }

    fn install_recorders() -> OpsReset {
        unsafe {
            PREDICATE_CALLS = 0;
            ERASE_CALLS = 0;
            let previous = ptr::read_volatile(ptr::addr_of!(REGISTERED_LISTENER_REMOVE_OPS));
            ptr::write_volatile(ptr::addr_of_mut!(REGISTERED_LISTENER_REMOVE_OPS), RegisteredListenerRemoveOps {
                pair_matches: record_pair_matches,
                erase: record_erase,
            });
            OpsReset(previous)
        }
    }

    #[test]
    fn skips_inactive_owner_and_removes_matching_successive_nodes() {
        let _lock = REGISTERED_LISTENER_REMOVE_TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::REGISTERED_LISTENER_REMOVE_BY_PAIR, 0x1000) else {
            note_missing_u32_fixture("app/registered_listener_remove_by_pair");
            return;
        };
        let _ops = install_recorders();

        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let owner = slab;
            registered_listener_remove_by_pair(owner, 7, 9);
            assert_eq!((PREDICATE_CALLS, ERASE_CALLS), (0, 0));

            let sentinel = slab.add(0x100).cast::<u32>();
            let first = slab.add(0x140).cast::<u32>();
            let second = slab.add(0x180).cast::<u32>();
            let third = slab.add(0x1c0).cast::<u32>();
            sentinel.write(first as usize as u32);
            first.write(second as usize as u32);
            second.write(third as usize as u32);
            third.write(sentinel as usize as u32);
            first.add(2).write(LISTENER_KEY_TAG);
            first.add(3).write(9);
            first.add(4).write(7);
            second.add(2).write(LISTENER_KEY_TAG);
            second.add(3).write(9);
            second.add(4).write(7);
            third.add(2).write(LISTENER_KEY_TAG);
            third.add(3).write(1);
            third.add(4).write(2);
            owner.add(LIST_HEAD_OFFSET).cast::<u32>().write(sentinel as usize as u32);
            owner.add(LIST_ACTIVE_OFFSET).cast::<u32>().write(1);

            registered_listener_remove_by_pair(owner, 7, 9);
            assert_eq!(PREDICATE_CALLS, 3);
            assert_eq!(ERASE_CALLS, 2);
        }
    }
}
