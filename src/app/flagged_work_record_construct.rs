//! Derived work-record constructor — `FUN_081dcf7c` @ `0x081dcf7c`.
//! True extent: 120 bytes (116 code + 4-byte vtable literal), ending at
//! `0x081dcff4`, the next real function boundary. Raw A32 decoding verifies
//! two inbound plain BL calls and zero predicated BL calls; the body has
//! three plain BL calls and zero predicated BL calls.
//!
//! Constructs the flagged base with (base_arg, 1, context), installs vtable
//! `0x0898e618`, stores words +0x70/+0x78, clears the pair at +0x7c, writes
//! the low bytes of the two flag arguments at +0x84/+0x85, clears +0x86/+0x87,
//! assigns the work-record value, and returns the base constructor's pointer.
//!
//! Deliberate deviations: Rust uses the existing semantic callee ports and
//! aligned word fields rather than reproducing register writeback arithmetic.
//! Flag arguments retain their full incoming ABI words until the byte stores.

use crate::app::work_record_assign_value::work_record_assign_value;
use crate::util::u32_pair_store::store_u32_pair;

#[cfg(target_os = "none")]
extern "C" {
    fn flagged_base_construct(this: *mut u8, arg1: u32, arg2: u32, arg3: u32) -> *mut u8;
}
#[cfg(not(target_os = "none"))]
use crate::app::flagged_base_construct::flagged_base_construct;

/// Constructs the derived record in valid, word-aligned caller storage.
/// The returned base storage must provide at least 0x88 writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn flagged_work_record_construct(
    this: *mut u8,
    first: u32,
    base_arg: u32,
    second: u32,
    first_flag: u32,
    second_flag: u32,
    value: u32,
    context: u32,
) -> *mut u8 {
    construct_with_base(this, first, base_arg, second, first_flag, second_flag,
        value, context, flagged_base_construct)
}

#[inline(always)]
unsafe fn construct_with_base(
    this: *mut u8, first: u32, base_arg: u32, second: u32,
    first_flag: u32, second_flag: u32, value: u32, context: u32,
    base: crate::app::flagged_base_construct::BaseConstructor,
) -> *mut u8 {
    let object = base(this, base_arg, 1, context);
    let words = object.cast::<u32>();
    words.write_volatile(0x0898_e618);
    words.add(0x1c).write_volatile(first);
    words.add(0x1e).write_volatile(second);
    let pair = store_u32_pair(words.add(0x1f), 0, 0).cast::<u8>();
    pair.add(8).write_volatile(first_flag as u8);
    pair.add(9).write_volatile(second_flag as u8);
    pair.add(10).write_volatile(0);
    pair.add(11).write_volatile(0);
    work_record_assign_value(object, value);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    // Return different storage, prefilled as a real base record. The value
    // is already assigned, so the real assignment port must preserve +0x3c.
    unsafe extern "C" fn base(this: *mut u8, value: u32, _: u32, _: u32) -> *mut u8 {
        let object = this.add(4);
        object.add(0x5c).cast::<u32>().write(value);
        object
    }

    #[test]
    fn initializes_returned_storage_without_clobbering_base_or_gaps() {
        for &(first, second, flag1, flag2, value) in &[
            (0, u32::MAX, 0, 0, 0),
            (u32::MAX, 0, 0x1234_56ff, 0xffff_ff80, u32::MAX),
        ] {
            let mut storage = [0xa5a5_a5a5u32; 37];
            let this = storage.as_mut_ptr().cast::<u8>();
            let object = unsafe {
                construct_with_base(this, first, value, second, flag1, flag2,
                    value, 0, base)
            };
            assert_eq!(object, unsafe { this.add(4) });
            let mut expected = [0xa5a5_a5a5u32; 37];
            expected[1] = 0x0898_e618;
            expected[1 + 0x5c / 4] = value;
            expected[1 + 0x70 / 4] = first;
            expected[1 + 0x78 / 4] = second;
            expected[1 + 0x7c / 4] = 0;
            expected[1 + 0x80 / 4] = 0;
            expected[1 + 0x84 / 4] = u32::from_le_bytes([flag1 as u8, flag2 as u8, 0, 0]);
            assert_eq!(storage, expected);
        }
    }
}
