//! Vtable-slot-0x40 result-word accessor.
//!
//! `vtable_slot_0x40_result_word` — original: `FUN_083d6aa8` @
//! **0x083d6aa8** (24 bytes; true extent `0x083d6aa8..0x083d6ac0`, with the
//! next distinct function beginning at `0x083d6ac0`). Raw ARM decoding finds
//! four direct incoming calls, all unconditional plain `bl` (at `0x08124040`,
//! `0x08298958`, `0x083d1300`, and `0x083d1344`); there are no predicated
//! direct `bl` calls. The body loads the object's vtable, calls slot `+0x40`
//! as `(object) -> *mut u32`, then returns the word at that result pointer.
//!
//! The slot's concrete target is runtime data and has no recovered static
//! identity. Deliberate deviation: host fixtures use a widened native-pointer
//! vtable representation; target builds load the original 32-bit object and
//! vtable words before the indirect call.


type ResultWordMethod = unsafe extern "C" fn(*mut u8) -> *mut u32;

const VTABLE_RESULT_WORD_SLOT: usize = 0x40 / 4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_result_word(object: *mut u8) -> *mut u32 {
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let method: ResultWordMethod = core::mem::transmute(vtable.add(VTABLE_RESULT_WORD_SLOT).read_volatile() as usize);
    method(object)
}

/// Host representation of the observed vtable slot.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostResultWordVtable {
    pub unresolved_00_to_3c: [usize; VTABLE_RESULT_WORD_SLOT],
    pub result_word: ResultWordMethod,
}

/// Host representation of an object whose first word is its vtable pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostResultWordObject {
    pub vtable: *const HostResultWordVtable,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_result_word(object: *mut u8) -> *mut u32 {
    let host_object = &*object.cast::<HostResultWordObject>();
    ((*host_object.vtable).result_word)(object)
}

/// Calls `object`'s vtable slot `+0x40` and returns the yielded result word.
///
/// # Safety
///
/// `object`, its vtable slot, and the pointer returned by that slot must all
/// be valid. retailOS performs no null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_0x40_result_word(object: *mut u8) -> u32 {
    dispatch_result_word(object).read_volatile()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVER: *mut u8 = ptr::null_mut();
    static mut CALLS: u32 = 0;
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_result_word(object: *mut u8) -> *mut u32 {
        RECEIVER = object;
        CALLS += 1;
        ptr::addr_of_mut!(RESULT)
    }

    fn fixture() -> (HostResultWordObject, HostResultWordVtable) {
        (
            HostResultWordObject { vtable: ptr::null() },
            HostResultWordVtable {
                unresolved_00_to_3c: [0; VTABLE_RESULT_WORD_SLOT],
                result_word: record_result_word,
            },
        )
    }

    #[test]
    fn dispatches_slot_40_with_the_original_object_and_returns_its_word() {
        let _guard = TEST_LOCK.lock();
        let (mut object, vtable) = fixture();
        object.vtable = &vtable;
        unsafe {
            RECEIVER = ptr::null_mut();
            CALLS = 0;
            RESULT = 0xdead_beef;
            let object_ptr = ptr::addr_of_mut!(object).cast::<u8>();
            assert_eq!(vtable_slot_0x40_result_word(object_ptr), 0xdead_beef);
            assert_eq!(RECEIVER, object_ptr);
            assert_eq!(CALLS, 1);
        }
    }

    #[test]
    fn propagates_zero_and_reloads_the_returned_word_each_call() {
        let _guard = TEST_LOCK.lock();
        let (mut object, vtable) = fixture();
        object.vtable = &vtable;
        unsafe {
            CALLS = 0;
            let object_ptr = ptr::addr_of_mut!(object).cast::<u8>();
            RESULT = 0;
            assert_eq!(vtable_slot_0x40_result_word(object_ptr), 0);
            RESULT = u32::MAX;
            assert_eq!(vtable_slot_0x40_result_word(object_ptr), u32::MAX);
            assert_eq!(CALLS, 2);
        }
    }
}
