//! Parameter template initialization — `FUN_0803bb60` @ `0x0803bb60`.
//!
//! Raw extent `0x0803bb60..0x0803bbe4`: 132 bytes, ending at the next
//! independent descriptor veneer. Three plain BL instructions, zero predicated
//! BL; one tail B to `0x080d3a78`. Ghidra incorrectly merges the tail target.
//! Bit 0 initializes an optional template through `0x080adf88`; ADB bits
//! 0x300 clear the output; collection bits 6 allocate an empty stack. Otherwise
//! resolve the template's item with flags & 0x400 and the incoming r3 context.
//! Allocation failure leaves the output untouched and records (13,133,65,0,0).
//!
//! Deliberate deviations: the tail B becomes a Rust call/return. The existing
//! ported stack factory and diagnostic service are reused. Unported optional
//! initialization and item resolution retain their verified retail addresses;
//! a generic internal worker permits host edge tests without executing firmware.

use crate::drivers::ata_cmd::ata_call_with_zero;
use crate::kernel::diag_ring_record::diag_ring_record;

#[inline(always)]
unsafe fn initialize(
    output: *mut u32,
    template: *const u32,
    context: u32,
    optional: impl FnOnce(*mut u32, *const u32),
    stack: impl FnOnce() -> *mut u32,
    resolve: impl FnOnce(*mut u32, *const u8, u32, u32) -> i32,
    allocation_error: impl FnOnce(),
) -> i32 {
    let flags = template.read();
    let item = template.add(4).read() as usize as *const u8;
    if flags & 1 != 0 {
        optional(output, template);
        return 1;
    }
    if flags & 0x300 != 0 {
        output.write(0);
        return 1;
    }
    if flags & 6 == 0 {
        return resolve(output, item, flags & 0x400, context);
    }
    let collection = stack();
    if collection.is_null() {
        allocation_error();
        return 0;
    }
    output.write(collection as usize as u32);
    1
}

/// Initialize an ASN.1-style template value; `incoming_r2` is not consumed.
/// The output and five-word template must be valid, aligned target words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parameter_template_new(
    output: *mut u32,
    template: *const u32,
    _incoming_r2: u32,
    context: u32,
) -> i32 {
    initialize(output, template, context,
        |out, tt| {
            let optional: unsafe extern "C" fn(*mut u32, *const u32) =
                core::mem::transmute(0x080a_df88usize);
            optional(out, tt);
        },
        || ata_call_with_zero(),
        |out, item, flags, ctx| {
            let resolve: unsafe extern "C" fn(*mut u32, *const u8, u32, u32) -> i32 =
                core::mem::transmute(0x080d_3a78usize);
            resolve(out, item, flags, ctx)
        },
        || diag_ring_record(13, 133, 65, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adb_precedes_collection_and_public_path_clears_output() {
        for flags in [0x100, 0x200, 0x306, 0x706] {
            let template = [flags, 0, 0, 0, 0];
            let mut output = 0xdeadbeef;
            assert_eq!(unsafe {
                parameter_template_new(&mut output, template.as_ptr(), 0, 7)
            }, 1);
            assert_eq!(output, 0);
        }
    }

    #[test]
    fn optional_precedes_adb_and_collection_without_overwriting_value() {
        let template = [0x707, 0, 0, 0, 0];
        let mut output = 42;
        assert_eq!(unsafe {
            initialize(&mut output, template.as_ptr(), 0,
                |out, _| { out.write(99); },
                || panic!("optional must not allocate a stack"),
                |_, _, _, _| panic!("optional must not resolve an item"),
                || panic!("optional must not report an allocation error"))
        }, 1);
        assert_eq!(output, 99);
    }

    #[test]
    fn collection_failure_preserves_output_and_reports_error() {
        for flags in [2, 4, 6, 0x406] {
            let template = [flags, 0, 0, 0, 0];
            let mut output = 0x12345678;
            let mut errors = 0;
            assert_eq!(unsafe {
                initialize(&mut output, template.as_ptr(), 0,
                    |_, _| panic!("not optional"), || core::ptr::null_mut(),
                    |_, _, _, _| panic!("collection must not resolve"),
                    || errors += 1)
            }, 0);
            assert_eq!(output, 0x12345678);
            assert_eq!(errors, 1);
        }
    }

    #[test]
    fn collection_success_stores_handle_without_item_resolution() {
        let template = [6, 0, 0, 0, 0];
        let mut output = 0;
        let mut handle = [0u32; 5];
        let pointer = handle.as_mut_ptr();
        assert_eq!(unsafe {
            initialize(&mut output, template.as_ptr(), 0,
                |_, _| panic!("not optional"), || pointer,
                |_, _, _, _| panic!("collection must not resolve"),
                || panic!("successful allocation must not report an error"))
        }, 1);
        assert_eq!(output, pointer as usize as u32);
    }
}
