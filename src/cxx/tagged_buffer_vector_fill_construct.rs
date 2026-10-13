//! Fill constructor for a vector of 16-byte tagged buffers.
//! Original: FUN_083e4210 @ 0x083e4210; true extent 140 bytes through
//! 0x083e429c (next function's push). One incoming plain BL, no incoming
//! predicated BL; body: one plain BL to operator_new_checked and one BLNE
//! to tagged_buffer_copy_construct.
//!
//! Zero the three vector words, allocate max(count, 32) << 4 bytes, then
//! copy-construct count elements from the same source. Skip construction
//! only when the current output address is zero, advancing by 16 regardless.
//! Store capacity end before logical end and return the vector address.
//! Deviations: call existing Rust ports directly; explicit wrapping u32
//! arithmetic preserves ARM shifts/address overflow and target-width fields
//! on hosts. The unused fourth caller argument and stack scratch are omitted.

use crate::cxx::tagged_buffer_copy_construct::tagged_buffer_copy_construct;
use crate::heap::new_handler::operator_new_checked;

/// # Safety
/// `vector` must point to three aligned writable u32 words. `source` must
/// address an aligned readable 16-byte tagged buffer whenever construction
/// occurs. Allocation must yield enough writable memory below 4 GiB on hosts;
/// nonzero cursors after a failed allocation must still be valid if visited,
/// exactly as required by retailOS (there is no allocation-failure bailout).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_buffer_vector_fill_construct(
    vector: *mut u32,
    count: u32,
    source: *const u8,
) -> *mut u32 {
    vector.write_volatile(0);
    vector.add(1).write_volatile(0);
    vector.add(2).write_volatile(0);
    let capacity = count.max(32);
    let allocation = operator_new_checked(capacity.wrapping_shl(4) as usize);
    vector.write_volatile(allocation as usize as u32);
    let mut cursor = allocation as usize as u32;
    let mut remaining = count;
    while remaining != 0 {
        if cursor != 0 {
            tagged_buffer_copy_construct(cursor as usize as *mut u8, source);
        }
        remaining -= 1;
        cursor = cursor.wrapping_add(16);
    }
    let begin = vector.read_volatile();
    vector.add(2).write_volatile(begin.wrapping_add(capacity.wrapping_shl(4)));
    vector.add(1).write_volatile(begin.wrapping_add(count.wrapping_shl(4)));
    vector
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, alloc_log};

    #[test]
    fn capacity_boundary_partial_copy_and_empty_source() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TAGGED_BUFFER_VECTOR_FILL_CONSTRUCT, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("tagged_buffer_vector_fill_construct");
            return;
        };
        let _lock = mock_heap();
        let source = [0x1234_5603u32, 0x9876_5432, 0x2468_ace0, 0x1357_9bdf];
        for count in [0u32, 1, 31, 32, 33] {
            unsafe {
                core::ptr::write_bytes(slab, 0xa5, 4096);
                set_alloc_ret(slab);
                let mut vector = [u32::MAX; 3];
                let pointer = vector.as_mut_ptr();
                let input = if count == 0 { core::ptr::null() } else { source.as_ptr().cast() };
                assert_eq!(tagged_buffer_vector_fill_construct(pointer, count, input), pointer);
                let begin = slab as usize as u32;
                assert_eq!(vector, [begin, begin + count * 16, begin + count.max(32) * 16]);
                assert_eq!(alloc_log().1, count.max(32) as usize * 16);
                let words = core::slice::from_raw_parts(slab.cast::<u32>(), 1024);
                for element in words[..count as usize * 4].chunks_exact(4) {
                    assert_eq!(element, [0xa5a5_a503, 0xa5a5_a5a5, source[2], source[3]]);
                }
                assert!(words[count as usize * 4..].iter().all(|word| *word == 0xa5a5_a5a5));
            }
        }
    }

    #[test]
    fn failed_allocation_skips_only_zero_cursor() {
        let _handler_lock = crate::heap::new_handler::tests::LOCK.lock()
            .unwrap_or_else(|error| panic!("handler test lock poisoned: {error}"));
        let _lock = mock_heap();
        set_alloc_ret(core::ptr::null_mut());
        for count in [0u32, 1] {
            let mut vector = [u32::MAX; 3];
            unsafe { tagged_buffer_vector_fill_construct(vector.as_mut_ptr(), count, core::ptr::null()); }
            assert_eq!(vector, [0, count * 16, 512]);
        }
    }
}
