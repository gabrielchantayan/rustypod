//! Selector/value record factory — `FUN_0813ecb4` @ `0x0813ecb4`.
//!
//! True extent: [0x0813ecb4, 0x0813ece4), 48 bytes: eleven A32
//! instructions plus the vtable literal at 0x0813ece0. The next real
//! function is the base constructor at 0x0813ece4. Whole-image word
//! decoding verifies two incoming plain BLs (0x0815f18c, 0x0815fb7c),
//! zero predicated incoming BLs, and two outgoing plain BLs with zero
//! predicated calls: operator_new and opaque_vtable_08985198_construct.
//!
//! Allocate twelve bytes, construct the base header, replace it with
//! vtable 0x08990b28, store the selector in word 1, then copy the referenced
//! value into word 2. Return the allocation unchanged in r0. Callers supply
//! a selector and a computed scalar; the concrete class remains unknown.
//! Deliberate deviations: no semantic changes. Correct Ghidra's void return;
//! use aligned volatile u32 accesses to retain the original access order
//! and target-width layout on hosts. Allocation uses the existing heap port.

pub const SELECTOR_VALUE_RECORD_VTABLE: u32 = 0x0899_0b28;

/// # Safety
/// `value` must address a readable aligned u32. The allocator must return
/// non-NULL storage for three aligned writable u32 words; like retailOS,
/// this function does not check allocation failure.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_value_record_create(selector: u32, value: *const u32) -> *mut u32 {
    let allocation = unsafe { crate::heap::veneers::operator_new(12) }.cast::<u32>();
    let record = unsafe { super::opaque_vtable_08985198_construct(allocation) };
    unsafe {
        record.write_volatile(SELECTOR_VALUE_RECORD_VTABLE);
        record.add(1).write_volatile(selector);
        let copied_value = value.read_volatile();
        record.add(2).write_volatile(copied_value);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};

    #[test]
    fn copies_scalar_bits_without_touching_source_or_adjacent_words() {
        let _lock = mock_heap();
        for (selector, value) in [(0, 0), (1, u32::MAX), (u32::MAX, 0x8000_0000)] {
            let mut words = [0xa5a5_5a5a; 5];
            let record = unsafe { words.as_mut_ptr().add(1) };
            set_alloc_ret(record.cast());
            let source = [0x1122_3344, value, 0x5566_7788];
            let returned = unsafe { selector_value_record_create(selector, source.as_ptr().add(1)) };
            assert_eq!(returned, record);
            assert_eq!(words, [0xa5a5_5a5a, SELECTOR_VALUE_RECORD_VTABLE,
                               selector, value, 0xa5a5_5a5a]);
            assert_eq!(source, [0x1122_3344, value, 0x5566_7788]);
        }
    }

    #[test]
    fn reads_aliased_source_after_header_and_selector_writes() {
        let _lock = mock_heap();
        for index in 0..3 {
            let mut words = [0xdead_beef; 3];
            let record = words.as_mut_ptr();
            set_alloc_ret(record.cast());
            let returned = unsafe { selector_value_record_create(0x7654_3210, record.add(index)) };
            let copied = [SELECTOR_VALUE_RECORD_VTABLE, 0x7654_3210, 0xdead_beef][index];
            assert_eq!(returned, record);
            assert_eq!(words, [SELECTOR_VALUE_RECORD_VTABLE, 0x7654_3210, copied]);
        }
    }
}
