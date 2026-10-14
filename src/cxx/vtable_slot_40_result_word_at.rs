//! Indexed virtual slot-`+0x40` result-word wrapper.
//!
//! `vtable_slot_40_result_word_at` — original: `FUN_083d6c2c` @
//! **0x083d6c2c** (24 bytes). Raw ARM establishes the exact extent from
//! `push {r4,lr}` at `0x083d6c2c` through `pop {r4,pc}` at `0x083d6c40`;
//! the separately linked next function begins at `0x083d6c44`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds four inbound
//! direct calls, all unconditional `bl` at `0x082113f4`, `0x08211df0`,
//! `0x083d1d5c`, and `0x083d1da4`; there are no predicated `bl` forms or
//! direct tail branches. The wrapper itself makes one indirect `blx` through
//! vtable word 16 (`+0x40`).
//!
//! # Algorithm
//!
//! Calls `receiver.vtable[16](receiver, index)`, then returns the first word
//! of the returned pointer. The raw body never writes `r1`, so `index` is
//! forwarded despite Ghidra omitting it from the recovered prototype. Neither
//! receiver, vtable, method result, nor its first word is NULL-checked.
//!
//! # Deliberate deviation
//!
//! The target vtable contains 32-bit entries while host function pointers are
//! wider. Rust therefore selects word index 16 in a host-sized vtable, then
//! performs the equivalent call and result-word load. The concrete virtual
//! method identity is not established and deliberately not invented.
//! An empty inline-assembly compiler barrier keeps this otherwise identical
//! wrapper a distinct exported BL target; it emits no ARM instruction.

/// ARMv5TE vtable word index for byte offset `+0x40`.
const RESULT_WORD_SLOT: usize = 0x40 / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x40`.
type VtableSlot40ResultAt = unsafe extern "C" fn(*mut u8, u32) -> *const u32;

/// Calls vtable slot `+0x40` with `index` and returns the first word of its result.
///
/// # Safety
///
/// `receiver` must be readable and contain a readable vtable pointer whose
/// word-16 entry is a valid [`VtableSlot40ResultAt`]. That method must return a
/// non-NULL pointer to a readable `u32`. No input is NULL-checked, matching
/// retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_40_result_word_at(receiver: *mut u8, index: u32) -> u32 {
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) };
    let vtable = unsafe { (receiver as *const *const VtableSlot40ResultAt).read() };
    let callback = unsafe { vtable.add(RESULT_WORD_SLOT).read() };
    let result = unsafe { callback(receiver, index) };
    unsafe { result.read() }
}

/// Indexed virtual slot-`+0x40` result-word wrapper.
///
/// `container_element_at_alias_5fbc` — original: `FUN_083d5fbc` @
/// **0x083d5fbc** (24 bytes; true extent `0x083d5fbc..0x083d5fd4`, with the
/// next independently linked function beginning at `0x083d5fd4`). Raw ARM
/// decoding finds three direct incoming calls, all unconditional plain `bl`
/// (at `0x08128448`, `0x08299d54`, and `0x0839c84c`); there are no predicated
/// direct `bl` calls. The body calls vtable word 16 (`+0x40`) with the live
/// `r1` index, then returns the first word of that result.
///
/// Ghidra's one-argument prototype and virtual-method return are wrong: raw
/// `blx r2` preserves `r1`, and the following `ldr r0,[r0]` loads the element
/// word. Deliberate deviation: host vtable entries use native-width function
/// pointers; selecting slot 16 preserves the target's four-byte slot layout.
/// The empty compiler barrier keeps this byte-identical sibling independently
/// hookable without emitting an ARM instruction.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn container_element_at_alias_5fbc(receiver: *mut u8, index: u32) -> u32 {
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) };
    let vtable = unsafe { (receiver as *const *const VtableSlot40ResultAt).read() };
    let callback = unsafe { vtable.add(RESULT_WORD_SLOT).read() };
    let result = unsafe { callback(receiver, index) };
    unsafe { result.read() }
}

/// Indexed virtual slot-`+0x40` result-word wrapper.
///
/// `container_element_at_alias_6844` — original: `FUN_083d6844` @
/// **0x083d6844** (24 bytes; true extent `0x083d6844..0x083d685c`, with the
/// next independently linked function beginning at `0x083d685c`). Raw ARM
/// decoding finds two direct incoming calls, both unconditional plain `bl`
/// (at `0x08298b34` and `0x083cfe78`); there are no predicated direct `bl`
/// calls. The body makes one indirect `blx` through vtable word 16 (`+0x40`).
///
/// # Algorithm
///
/// Calls `receiver.vtable[16](receiver, index)`, then returns the first word
/// of the returned pointer. The raw body preserves `r1`, so `index` is
/// forwarded despite Ghidra omitting it from the recovered prototype. Neither
/// receiver, vtable, method result, nor its first word is NULL-checked.
///
/// # Deliberate deviation
///
/// The target vtable contains 32-bit entries while host function pointers are
/// wider. Rust selects word index 16 in a host-sized vtable, preserving the
/// target slot. A dedicated text section and empty compiler barrier keep this
/// byte-identical sibling a distinct exported BL target. LLVM uses `fp` rather
/// than retailOS's unused `r4` for its equivalent stack-alignment save.
/// Neither choice changes the ARM call or return contract.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_6844")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn container_element_at_alias_6844(receiver: *mut u8, index: u32) -> u32 {
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) };
    let vtable = unsafe { (receiver as *const *const VtableSlot40ResultAt).read() };
    let callback = unsafe { vtable.add(RESULT_WORD_SLOT).read() };
    let result = unsafe { callback(receiver, index) };
    unsafe { result.read() }
}

/// Indexed container element-word getter.
///
/// Original: `FUN_083d5fd4` at `0x083d5fd4`, 24 bytes, ending at the next
/// real prologue at `0x083d5fec`. Whole-image raw A32 decoding finds one
/// incoming plain BL (`0x0839c928`) and zero predicated BLs. The body has
/// zero plain or predicated BLs and one unconditional indirect BLX.
/// Invoke vtable word 16 (`+0x40`) with `(receiver, index)`, then load the
/// first u32 from the returned slot. The caller supplies its live r1 index;
/// Ghidra's one-argument prototype is incomplete. No NULL checks.
///
/// Deliberate deviations: host vtables use native-width function pointers
/// indexed by target word number. A dedicated section and empty compiler
/// barrier preserve this identical sibling as an independently hookable
/// symbol without adding an ARM instruction. Concrete method identity is
/// unresolved; no fixed-address callee is assumed.
///
/// # Safety
/// Receiver and vtable word 16 must be valid for the indexed method ABI;
/// the method must return a nonnull aligned pointer to a readable u32.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.container_element_at_alias_5fd4")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn container_element_at_alias_5fd4(receiver: *mut u8, index: u32) -> u32 {
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) };
    let vtable = unsafe { (receiver as *const *const VtableSlot40ResultAt).read() };
    let callback = unsafe { vtable.add(RESULT_WORD_SLOT).read() };
    let result = unsafe { callback(receiver, index) };
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
    static mut DISPATCH_CALLS: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _index: u32) -> *const u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        core::ptr::null()
    }

    unsafe extern "C" fn record_dispatch(receiver: *mut u8, index: u32) -> *const u32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_INDEX = index;
            DISPATCH_CALLS += 1;
            core::ptr::addr_of!(RESULT)
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            FORWARDED_INDEX = 0;
            DISPATCH_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
            RESULT = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_only_slot_40_forwards_index_and_loads_returned_word() {
        let _bench = bench();
        let mut vtable = [wrong_slot as VtableSlot40ResultAt; RESULT_WORD_SLOT + 1];
        vtable[RESULT_WORD_SLOT] = record_dispatch;
        let mut receiver = vtable.as_ptr() as *mut u8;
        unsafe { RESULT = 0xa5a5_5a5a };

        assert_eq!(unsafe { vtable_slot_40_result_word_at(&mut receiver as *mut _ as *mut u8, 0x7fff_ffff) }, 0xa5a5_5a5a);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, (&mut receiver as *mut *mut u8) as usize);
        assert_eq!(unsafe { FORWARDED_INDEX }, 0x7fff_ffff);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x40 dispatches");
    }

    #[test]
    fn alias_5fbc_forwards_zero_index_and_loads_zero_element() {
        let _bench = bench();
        let mut vtable = [wrong_slot as VtableSlot40ResultAt; RESULT_WORD_SLOT + 1];
        vtable[RESULT_WORD_SLOT] = record_dispatch;
        let mut receiver = vtable.as_ptr() as *mut u8;

        assert_eq!(unsafe { container_element_at_alias_5fbc(&mut receiver as *mut _ as *mut u8, 0) }, 0);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, (&mut receiver as *mut *mut u8) as usize);
        assert_eq!(unsafe { FORWARDED_INDEX }, 0);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x40 dispatches");
    }

    #[test]
    fn alias_6844_forwards_high_bit_index_and_loads_returned_word() {
        let _bench = bench();
        let mut vtable = [wrong_slot as VtableSlot40ResultAt; RESULT_WORD_SLOT + 1];
        vtable[RESULT_WORD_SLOT] = record_dispatch;
        let mut receiver = vtable.as_ptr() as *mut u8;
        unsafe { RESULT = 0x8bad_f00d };

        assert_eq!(unsafe { container_element_at_alias_6844(&mut receiver as *mut _ as *mut u8, 0x8000_0001) }, 0x8bad_f00d);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, (&mut receiver as *mut *mut u8) as usize);
        assert_eq!(unsafe { FORWARDED_INDEX }, 0x8000_0001);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x40 dispatches");
    }

    #[repr(C)]
    struct IndexedWords {
        vtable: *const VtableSlot40ResultAt,
        words: [u32; 3],
        last: [u32; 2],
    }

    unsafe extern "C" fn indexed_word_slot(receiver: *mut u8, index: u32) -> *const u32 {
        let words = receiver.cast::<IndexedWords>();
        if index == u32::MAX {
            unsafe { core::ptr::addr_of!((*words).last).cast::<u32>() }
        } else {
            unsafe { core::ptr::addr_of!((*words).words).cast::<u32>().add(index as usize) }
        }
    }

    #[test]
    fn alias_5fd4_reads_selected_word_including_zero_and_full_width_values() {
        let vtable = [indexed_word_slot as VtableSlot40ResultAt; RESULT_WORD_SLOT + 1];
        let mut words = IndexedWords {
            vtable: vtable.as_ptr(), words: [0, 0x8000_0000, u32::MAX],
            last: [0x1234_abcd, 0xfeed_beef],
        };
        for (index, expected) in [(0, 0), (1, 0x8000_0000), (2, u32::MAX), (u32::MAX, 0x1234_abcd)] {
            assert_eq!(unsafe { container_element_at_alias_5fd4((&mut words as *mut IndexedWords).cast(), index) }, expected);
        }
        words.words[1] = 7;
        assert_eq!(unsafe { container_element_at_alias_5fd4((&mut words as *mut IndexedWords).cast(), 1) }, 7);
        assert_eq!(words.last[1], 0xfeed_beef);
    }
}
