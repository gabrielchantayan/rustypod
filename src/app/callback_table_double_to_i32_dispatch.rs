//! `callback_table_double_to_i32_dispatch` — original: `FUN_080620ac` @
//! **0x080620ac** (76 bytes, `0x080620ac..0x080620f7`).
//!
//! Raw instruction words establish two unconditional direct `bl` instructions
//! (`callback_table_get` and `__d2i`), zero predicated `bl` forms, and a tail
//! `bx` through callback-table word `+0x0c`. There are three verified direct
//! inbound plain `bl` instructions (0x08062190, 0x08062298, and 0x0808b318)
//! and zero predicated direct calls; Ghidra's fourth caller is not a raw
//! branch-immediate call.
//!
//! Algorithm: load the lazily cached callback table; if both it and its word
//! `+0x0c` are non-null, convert the incoming soft-float double bit pattern to
//! `i32` with `__d2i`, then tail-dispatch `(context, value, converted)`.
//!
//! Deliberate deviations: host tables use native-width callback fields rather
//! than target 32-bit words, preserving the slot without truncating a host
//! function pointer. Rust returns after the callback instead of expressing the
//! ARM tail branch; the wrapper has a void ABI, so this is observable-equivalent.

use crate::app::callback_table::callback_table_get;

const CALLBACK_TABLE_DOUBLE_TO_I32_WORD: usize = 3;
type Callback = unsafe extern "C" fn(*mut u8, u32, i32);

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostCallbackTable {
    pub unresolved_00_to_08: [usize; CALLBACK_TABLE_DOUBLE_TO_I32_WORD],
    pub dispatch_double_as_i32: Option<Callback>,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch(table: *mut u8, context: *mut u8, value: u32, double_bits: u64) {
    let address = unsafe {
        core::ptr::read_volatile(table.cast::<u32>().add(CALLBACK_TABLE_DOUBLE_TO_I32_WORD))
    };
    if address != 0 {
        let callback: Callback = unsafe { core::mem::transmute(address as usize) };
        unsafe { callback(context, value, crate::fp::fp_dconv::__d2i(double_bits)) };
    }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch(table: *mut u8, context: *mut u8, value: u32, double_bits: u64) {
    let table = unsafe { &*table.cast::<HostCallbackTable>() };
    if let Some(callback) = table.dispatch_double_as_i32 {
        unsafe { callback(context, value, crate::fp::fp_dconv::__d2i(double_bits)) };
    }
}

/// Converts a soft-float double to `i32` and dispatches callback-table slot +0xc.
///
/// # Safety
///
/// The callback table returned by `callback_table_get` must have the recovered
/// target layout. Its +0xc callback, when non-null, must accept these arguments.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_table_double_to_i32_dispatch(
    context: *mut u8,
    value: u32,
    double_bits: u64,
) {
    let table = unsafe { callback_table_get() };
    if !table.is_null() {
        unsafe { dispatch(table, context, value, double_bits) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::callback_table::tests::{
        reset_callback_table_for_test, CALLBACK_TABLE_TEST_LOCK,
    };
    static mut OBSERVED: Option<(*mut u8, u32, i32)> = None;

    unsafe extern "C" fn record(context: *mut u8, value: u32, converted: i32) {
        unsafe { OBSERVED = Some((context, value, converted)) };
    }

    #[test]
    fn dispatches_truncated_double_through_word_three() {
        let _lock = CALLBACK_TABLE_TEST_LOCK.lock();
        let mut context = 0u8;
        let table = HostCallbackTable {
            unresolved_00_to_08: [0; CALLBACK_TABLE_DOUBLE_TO_I32_WORD],
            dispatch_double_as_i32: Some(record),
        };
        unsafe {
            OBSERVED = None;
            reset_callback_table_for_test((&table as *const HostCallbackTable).cast_mut().cast());
            callback_table_double_to_i32_dispatch(&mut context, 0x20, (-12.75f64).to_bits());
        }
        assert_eq!(unsafe { OBSERVED }, Some((&mut context as *mut u8, 0x20, -12)));
    }

    #[test]
    fn null_callback_slot_skips_conversion_dispatch() {
        let _lock = CALLBACK_TABLE_TEST_LOCK.lock();
        let table = HostCallbackTable {
            unresolved_00_to_08: [0; CALLBACK_TABLE_DOUBLE_TO_I32_WORD],
            dispatch_double_as_i32: None,
        };
        unsafe {
            OBSERVED = None;
            reset_callback_table_for_test((&table as *const HostCallbackTable).cast_mut().cast());
            callback_table_double_to_i32_dispatch(core::ptr::null_mut(), 0, f64::INFINITY.to_bits());
        }
        assert_eq!(unsafe { OBSERVED }, None);
    }
}
