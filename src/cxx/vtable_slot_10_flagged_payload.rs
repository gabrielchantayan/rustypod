//! `vtable_slot_10_flagged_payload` — retailOS `FUN_081fcef0` at
//! `0x081fcef0`, 44 bytes (`0x081fcef0..0x081fcf1c`). The next real
//! function starts with `push {r4-r8,lr}` at `0x081fcf1c`.
//! Whole-image raw ARM decoding finds two plain inbound BL calls at
//! `0x081f06c8` and `0x081f0e34`, no predicated BL or direct B callers.
//! The body has one plain BL, no predicated BL, and one indirect BLX.
//!
//! Dispatches vtable slot +0x10 with the object and unchanged index. A NULL
//! result returns NULL; otherwise the existing flagged-pair accessor returns
//! the payload address at +4 only when the result's flag byte at +8 is odd.
//! Raw callers establish the index argument omitted by Ghidra. The virtual
//! method's concrete identity remains unrecovered.
//!
//! Deliberate deviation: host vtables use native-width entries at word index
//! four; on ARM these are the original four-byte entries. Flagged records
//! retain their original byte layout on both targets.

use super::flagged_pair_copy::FlaggedPair;
use super::flagged_pair_payload::flagged_pair_payload_if_set;

const FLAGGED_RECORD_SLOT: usize = 0x10 / 4;
type FlaggedRecordMethod = unsafe extern "C" fn(*mut u8, u32) -> *mut FlaggedPair;

/// Returns the optional flagged payload selected by a virtual indexed lookup.
///
/// # Safety
/// `object` must contain a valid vtable pointer whose word-four entry has the
/// `FlaggedRecordMethod` ABI. Any non-NULL result must be readable at byte +8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_slot_10_flagged_payload(object: *mut u8, index: u32) -> *mut u8 {
    let vtable = unsafe { object.cast::<*const usize>().read() };
    let entry = unsafe { vtable.add(FLAGGED_RECORD_SLOT).read() };
    let method: FlaggedRecordMethod = unsafe { core::mem::transmute(entry) };
    let record = unsafe { method(object, index) };
    if record.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { flagged_pair_payload_if_set(record) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        record: *mut FlaggedPair,
        observed_index: u32,
        calls: u32,
    }

    unsafe extern "C" fn lookup(object: *mut u8, index: u32) -> *mut FlaggedPair {
        let object = unsafe { &mut *object.cast::<Object>() };
        object.observed_index = index;
        object.calls += 1;
        object.record
    }

    unsafe extern "C" fn wrong_slot(_: *mut u8, _: u32) -> *mut FlaggedPair {
        panic!("wrong vtable slot");
    }

    #[test]
    fn null_virtual_result_is_not_dereferenced() {
        let vtable = [wrong_slot as usize, wrong_slot as usize, wrong_slot as usize,
            wrong_slot as usize, lookup as usize];
        let mut object = Object { vtable: vtable.as_ptr(), record: core::ptr::null_mut(),
            observed_index: 0, calls: 0 };
        let result = unsafe {
            vtable_slot_10_flagged_payload((&mut object as *mut Object).cast(), u32::MAX)
        };
        assert!(result.is_null());
        assert_eq!(object.observed_index, u32::MAX);
        assert_eq!(object.calls, 1);
    }

    #[test]
    fn all_flag_bytes_select_payload_by_low_bit_without_mutating_record() {
        let vtable = [wrong_slot as usize, wrong_slot as usize, wrong_slot as usize,
            wrong_slot as usize, lookup as usize];
        for flag in 0..=255u32 {
            let mut words = [0x1122_3344u32, 0xdead_beef, 0xaabb_cc00 | flag];
            let original = words;
            let mut object = Object { vtable: vtable.as_ptr(),
                record: words.as_mut_ptr().cast(), observed_index: u32::MAX, calls: 0 };
            let result = unsafe {
                vtable_slot_10_flagged_payload((&mut object as *mut Object).cast(), flag)
            };
            let expected = if flag & 1 == 0 { core::ptr::null_mut() }
                else { unsafe { words.as_mut_ptr().add(1).cast::<u8>() } };
            assert_eq!(result, expected, "flag {flag}");
            assert_eq!(object.observed_index, flag);
            assert_eq!(object.calls, 1);
            assert_eq!(words, original);
        }
    }
}
