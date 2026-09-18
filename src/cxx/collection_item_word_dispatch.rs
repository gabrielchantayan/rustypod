//! Collection item-word virtual dispatch.
//!
//! `collection_item_word_dispatch` — original: `FUN_081d0e00` @
//! **0x081d0e00**, 24 bytes (`0x081d0e00..0x081d0e18`; the independently
//! linked next function begins at `0x081d0e18` with `push {r3,r4,r5,r6,r7,lr}`).
//! Whole-image decoding of every ARM `B`/`BL` immediate finds exactly four
//! inbound direct calls, all unconditional plain `bl` at `0x0815dfc4`,
//! `0x0815dff4`, `0x0815e468`, and `0x081d0e54`; there are no predicated
//! `bl` forms. The body has no direct `bl`: it performs one unconditional
//! indirect `blx` through vtable slot `+0x40`.
//!
//! # Algorithm
//!
//! Treats `collection` as a pointer four bytes past a polymorphic object's
//! vtable field. It pre-decrements that pointer, invokes vtable slot `+0x40`
//! with the recovered object pointer and unchanged `index`, then returns the
//! first word of the method's non-NULL result. Neither pointer is checked.
//!
//! # Deliberate deviation
//!
//! The retail vtable stores 32-bit function pointers; host function pointers
//! are wider, so this implementation indexes a host-sized vtable by word
//! rather than using retail byte offsets. The virtual method's concrete
//! identity is not established and is deliberately not invented.

/// ARMv5TE vtable word index for byte offset `+0x40`.
const ITEM_WORD_SLOT: usize = 0x40 / 4;

/// ABI of the unrecovered collection virtual method.
type CollectionItemWordMethod = unsafe extern "C" fn(*mut u8, u32) -> *const u32;

/// Dispatches to a collection's slot-`+0x40` method and loads its result word.
///
/// # Safety
///
/// `collection` must point immediately after a readable vtable-pointer word.
/// That vtable's word-16 entry must be a valid [`CollectionItemWordMethod`],
/// and its returned pointer must be non-NULL and readable. No inputs are
/// NULL-checked, matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_item_word_dispatch(collection: *mut u8, index: u32) -> u32 {
    let receiver = unsafe { collection.sub(core::mem::size_of::<u32>()) };
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(ITEM_WORD_SLOT).read() };
    let method: CollectionItemWordMethod = unsafe { core::mem::transmute(entry) };
    let result = unsafe { method(receiver, index) };
    unsafe { result.read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut FORWARDED_INDEX: u32 = 0;
    static mut RESULT_WORD: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn item_method(receiver: *mut u8, index: u32) -> *const u32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_INDEX = index;
            core::ptr::addr_of!(RESULT_WORD)
        }
    }

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _index: u32) -> *const u32 {
        unsafe {
            WRONG_SLOT_CALLS += 1;
            core::ptr::addr_of!(RESULT_WORD)
        }
    }

    #[repr(C)]
    struct CollectionFixture {
        vtable: *const usize,
        trailing_collection_word: u32,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            FORWARDED_INDEX = 0;
            RESULT_WORD = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn restores_receiver_forwards_index_and_loads_result_word() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; ITEM_WORD_SLOT + 1];
        vtable[ITEM_WORD_SLOT] = item_method as usize;
        let mut collection = CollectionFixture {
            vtable: vtable.as_ptr(),
            trailing_collection_word: 0,
        };
        let receiver = (&mut collection as *mut CollectionFixture).cast::<u8>();
        let argument = unsafe { receiver.add(core::mem::size_of::<u32>()) };
        unsafe { RESULT_WORD = 0x9a4e_71c3 };

        let result = unsafe { collection_item_word_dispatch(argument, u32::MAX) };

        assert_eq!(unsafe { FORWARDED_RECEIVER }, receiver as usize);
        assert_eq!(unsafe { FORWARDED_INDEX }, u32::MAX);
        assert_eq!(result, 0x9a4e_71c3);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x40 dispatches");
    }
}
