//! `vtable_slot_10_optional_word` — original: `FUN_081fca8c` @
//! **0x081fca8c**, 36 bytes (`0x081fca8c..0x081fcab0`; the independently
//! linked next function begins at `0x081fcab0` with `push {r4,lr}`).
//! Whole-image decoding of every ARM `B`/`BL` immediate finds exactly three
//! inbound direct calls, all unconditional plain `bl` at `0x081f01a8`,
//! `0x081f0f70`, and `0x08214c90`; there are no predicated `bl` forms. The
//! body has no direct `bl`: it makes one indirect `blx` through vtable slot
//! `+0x10`.
//!
//! # Algorithm
//!
//! Calls the object's slot-`+0x10` virtual method with the unchanged `index`.
//! It returns `u32::MAX` when that method returns NULL; otherwise it loads and
//! returns the first word of the method result. The object, vtable, slot, and
//! non-NULL result are unchecked, matching retailOS.
//!
//! # Deliberate deviation
//!
//! The retail vtable stores 32-bit function pointers. Host function pointers
//! are wider, so the host representation indexes native-width vtable entries;
//! target builds retain the observed four-byte word index. The virtual method's
//! concrete identity is not established and is deliberately not invented.

/// ARMv5TE vtable word index for byte offset `+0x10`.
const OPTIONAL_WORD_SLOT: usize = 0x10 / 4;

/// ABI of the unrecovered virtual method.
type OptionalWordMethod = unsafe extern "C" fn(*mut u8, u32) -> *const u32;

/// Dispatches to slot `+0x10` and returns its optional result word.
///
/// # Safety
///
/// `object` must begin with a readable vtable-pointer word. Its vtable's
/// word-4 entry must be a valid [`OptionalWordMethod`]. If that method returns
/// non-NULL, the result must point to a readable `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_slot_10_optional_word(object: *mut u8, index: u32) -> u32 {
    let vtable = unsafe { (object as *const *const usize).read() };
    let entry = unsafe { vtable.add(OPTIONAL_WORD_SLOT).read() };
    let method: OptionalWordMethod = unsafe { core::mem::transmute(entry) };
    let result = unsafe { method(object, index) };

    if result.is_null() {
        u32::MAX
    } else {
        unsafe { result.read() }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_OBJECT: usize = 0;
    static mut FORWARDED_INDEX: u32 = 0;
    static mut RESULT_WORD: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn returning_method(object: *mut u8, index: u32) -> *const u32 {
        unsafe {
            FORWARDED_OBJECT = object as usize;
            FORWARDED_INDEX = index;
            core::ptr::addr_of!(RESULT_WORD)
        }
    }

    unsafe extern "C" fn null_method(_object: *mut u8, _index: u32) -> *const u32 {
        core::ptr::null()
    }

    unsafe extern "C" fn wrong_slot(_object: *mut u8, _index: u32) -> *const u32 {
        unsafe {
            WRONG_SLOT_CALLS += 1;
            core::ptr::addr_of!(RESULT_WORD)
        }
    }

    #[repr(C)]
    struct ObjectFixture {
        vtable: *const usize,
        payload: u32,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_OBJECT = 0;
            FORWARDED_INDEX = 0;
            RESULT_WORD = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_slot_10_forwards_index_and_loads_result_word() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; OPTIONAL_WORD_SLOT + 1];
        vtable[OPTIONAL_WORD_SLOT] = returning_method as usize;
        let mut object = ObjectFixture {
            vtable: vtable.as_ptr(),
            payload: 0,
        };
        unsafe { RESULT_WORD = 0x9a4e_71c3 };

        let result = unsafe {
            vtable_slot_10_optional_word((&mut object as *mut ObjectFixture).cast(), u32::MAX)
        };

        assert_eq!(unsafe { FORWARDED_OBJECT }, (&mut object as *mut ObjectFixture) as usize);
        assert_eq!(unsafe { FORWARDED_INDEX }, u32::MAX);
        assert_eq!(result, 0x9a4e_71c3);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x10 dispatches");
    }

    #[test]
    fn returns_all_ones_when_virtual_method_returns_null() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; OPTIONAL_WORD_SLOT + 1];
        vtable[OPTIONAL_WORD_SLOT] = null_method as usize;
        let mut object = ObjectFixture {
            vtable: vtable.as_ptr(),
            payload: 0,
        };

        let result = unsafe { vtable_slot_10_optional_word((&mut object as *mut ObjectFixture).cast(), 7) };

        assert_eq!(result, u32::MAX);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "the null path still selects slot +0x10");
    }
}
