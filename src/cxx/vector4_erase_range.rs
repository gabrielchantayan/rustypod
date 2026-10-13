/// vector4_erase_range — original: `FUN_083e5140` @ 0x083e5140 (84 bytes).
///
/// Erases [first,last) from a vector of trivial four-byte elements. Unless
/// begin equals end, copies [last,end) forward to first, then subtracts the
/// erased byte count (masked to a word boundary) from the vector's end.
/// Returns first; begin, capacity, and the unused tail storage are preserved.
///
/// Raw extent: 21 ARM words through pop {r4,pc}; the next function starts at
/// 0x083e5194. Zero outbound BLs (plain or predicated); one inbound BL, the
/// predicated blhi at 0x08104a04, and zero plain inbound BLs. That caller
/// passes end in r2 despite Ghidra omitting its third argument. Deliberate
/// deviation: omit the memory-free cursor loop for trivial destruction.
/// Volatile word transfers prevent LLVM from substituting a libc copy call.
///
/// # Safety
/// `vector` addresses readable begin/end target-width words, with writable
/// end. For a nonempty vector, first and last are aligned ordered cursors
/// within its allocation, first <= last <= end; [last,end) is readable and
/// its destination at first is writable. The vector head must not alias the
/// element storage. Empty vectors do not dereference either cursor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector4_erase_range(
    vector: *mut u32,
    first: *mut u32,
    last: *const u32,
) -> *mut u32 {
    let end = unsafe { vector.add(1).read() as usize as *const u32 };
    if unsafe { vector.read() as usize as *const u32 } != end {
        let mut source = last;
        let mut destination = first;
        while source != end {
            unsafe {
                destination.write_volatile(source.read_volatile());
                source = source.add(1);
                destination = destination.add(1);
            }
        }
        let erased_bytes = (last as usize).wrapping_sub(first as usize) as u32 & !3;
        let current_end = unsafe { vector.add(1).read() };
        unsafe { vector.add(1).write(current_end.wrapping_sub(erased_bytes)) };
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn all_valid_ranges_preserve_prefix_tail_and_capacity() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::VECTOR4_ERASE_RANGE, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/vector4_erase_range"));
            return;
        };
        let elements = base.cast::<u32>();
        for len in 0..=8 {
            for first in 0..=len {
                for last in first..=len {
                    let original = [11u32, 22, 33, 44, 55, 66, 77, 88, 99];
                    let mut expected = original;
                    expected[first..first + len - last].copy_from_slice(&original[last..len]);
                    unsafe {
                        for (index, value) in original.iter().enumerate() {
                            elements.add(index).write(*value);
                        }
                        let begin = elements as usize as u32;
                        let capacity = elements.add(9) as usize as u32;
                        let mut vector = [begin, elements.add(len) as usize as u32, capacity];
                        let position = elements.add(first);
                        assert_eq!(vector4_erase_range(vector.as_mut_ptr(), position, elements.add(last)), position);
                        assert_eq!(vector, [begin, elements.add(len - (last - first)) as usize as u32, capacity]);
                        assert_eq!(core::slice::from_raw_parts(elements, 9), &expected);
                    }
                }
            }
        }
    }

    #[test]
    fn empty_null_vector_does_not_access_cursors() {
        let mut vector = [0u32, 0, 0x1234];
        let first = core::ptr::null_mut();
        unsafe {
            assert_eq!(vector4_erase_range(vector.as_mut_ptr(), first, core::ptr::null()), first);
        }
        assert_eq!(vector, [0, 0, 0x1234]);
    }
}
