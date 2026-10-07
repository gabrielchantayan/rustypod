//! Two-word value record factory — `FUN_0813ec80` @ `0x0813ec80`.
//!
//! True extent: [0x0813ec80, 0x0813ecb4), 52 bytes: twelve A32
//! instructions and the vtable literal at 0x0813ecb0. The next real
//! function begins with PUSH at 0x0813ecb4. Raw word decoding verifies
//! two outgoing plain BLs, zero predicated BLs, and two incoming plain
//! BLs (0x0815f140, 0x0815fb88), with zero predicated incoming BLs.
//!
//! Allocate twelve bytes, call the base-header constructor, replace the
//! header with vtable 0x089908d8, then read and store each of the two
//! source words in order. Return the constructed allocation in r0.
//! Callers consume this as a polymorphic value record; class identity is
//! unknown. Deliberate deviations: correct Ghidra's void return, retain
//! target-width aligned volatile accesses and alias-sensitive ordering.
//! Both callees use existing ports; no semantic changes or new seams.

pub const TWO_WORD_VALUE_RECORD_VTABLE: u32 = 0x0899_08d8;

/// # Safety
/// `source` must address two readable aligned u32 words. The allocator
/// must return non-NULL storage for three writable aligned u32 words.
/// As in retailOS, allocation failure is not checked. Source may alias
/// the allocation, provided each access remains valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_word_value_record_create(source: *const u32) -> *mut u32 {
    let allocation = unsafe { crate::heap::veneers::operator_new(12) }.cast::<u32>();
    let record = unsafe { super::opaque_vtable_08985198_construct(allocation) };
    unsafe {
        record.write_volatile(TWO_WORD_VALUE_RECORD_VTABLE);
        let first = source.read_volatile();
        record.add(1).write_volatile(first);
        let second = source.add(1).read_volatile();
        record.add(2).write_volatile(second);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};

    #[test]
    fn copies_full_width_words_without_touching_source_or_neighbors() {
        let _lock = mock_heap();
        for payload in [[0, u32::MAX], [u32::MAX, 0], [0x8000_0000, 0x1234_5678]] {
            let mut words = [0xa5a5_5a5a; 5];
            let record = unsafe { words.as_mut_ptr().add(1) };
            set_alloc_ret(record.cast());
            let source = [0x1122_3344, payload[0], payload[1], 0x5566_7788];
            let returned = unsafe { two_word_value_record_create(source.as_ptr().add(1)) };
            assert_eq!(returned, record);
            assert_eq!(words, [0xa5a5_5a5a, TWO_WORD_VALUE_RECORD_VTABLE,
                               payload[0], payload[1], 0xa5a5_5a5a]);
            assert_eq!(source, [0x1122_3344, payload[0], payload[1], 0x5566_7788]);
        }
    }

    #[test]
    fn aliasing_observes_header_and_first_payload_write() {
        let _lock = mock_heap();
        for index in 0..3 {
            let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
            let record = words.as_mut_ptr();
            set_alloc_ret(record.cast());
            unsafe { two_word_value_record_create(record.add(index)) };
            let expected = match index {
                0 => [TWO_WORD_VALUE_RECORD_VTABLE, TWO_WORD_VALUE_RECORD_VTABLE,
                      TWO_WORD_VALUE_RECORD_VTABLE, 0x4444_4444],
                1 => [TWO_WORD_VALUE_RECORD_VTABLE, 0x2222_2222, 0x3333_3333, 0x4444_4444],
                _ => [TWO_WORD_VALUE_RECORD_VTABLE, 0x3333_3333, 0x4444_4444, 0x4444_4444],
            };
            assert_eq!(words, expected);
        }
    }
}
