//! Word-vector copy constructor — original: `FUN_083e4a90` at load address
//! `0x083e4a90`.
//!
//! Raw `osos.dec` establishes the exact 156-byte extent: 39 ARM words from
//! `push {r2,r3,r4,r5,r6,lr}` at `0x083e4a90` through
//! `pop {r2,r3,r4,r5,r6,pc}` at `0x083e4b28`; `0x083e4b2c` starts the next
//! separately linked function. The body has three plain unconditional outbound
//! `bl` instructions (two calls to `vector_size_elem4_alias_78e4` at
//! `0x083d78e4`, one to `operator_new_checked` at `0x08266c70`) and no
//! predicated outbound calls.
//!
//! It initializes a three-word `{begin, end, capacity_end}` vector, allocates
//! `max(source_len, 32)` four-byte slots, copies each source word when the
//! allocation succeeds, and sets end and capacity_end from the source length
//! and selected capacity. Deliberate deviation: Rust calls the ported checked
//! allocator directly rather than reproducing the ARM call instruction; target
//! pointers remain u32 words so host pointer width cannot alter the layout.
//!
//! On target, the two size calculations call the existing port of
//! `vector_size_elem4_alias_78e4`; host builds calculate from target-width
//! words because `VectorBounds` deliberately uses native host pointers there.

#[cfg(target_os = "none")]
use crate::cxx::templates::{vector_size_elem4_alias_78e4, VectorBounds};

use crate::heap::veneers::operator_new_checked;

/// Copy-constructs a target-layout vector of four-byte words into `output`.
///
/// # Safety
///
/// `output` must identify three writable target-width words. `source` must
/// identify three target-width vector bounds, with a readable word range from
/// begin through end. The checked allocator's result must have room for the
/// selected capacity when non-NULL, as retailOS assumes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_word_copy_construct(output: *mut u32, source: *const u32) -> *mut u32 {
    output.write(0);
    output.add(1).write(0);
    output.add(2).write(0);

    let source_begin = source.read() as usize as *const u32;
    let source_end = source.add(1).read() as usize as *const u32;
    #[cfg(target_os = "none")]
    let source_len = vector_size_elem4_alias_78e4(source.cast::<VectorBounds>()) as u32 as usize;
    #[cfg(not(target_os = "none"))]
    let source_len = (source_end as usize).wrapping_sub(source_begin as usize) >> 2;
    let capacity = core::cmp::max(source_len, 32);
    let allocation = operator_new_checked(capacity * core::mem::size_of::<u32>()).cast::<u32>();
    output.write(allocation as usize as u32);

    let mut input = source_begin;
    let mut destination = allocation;
    while input != source_end {
        if !destination.is_null() {
            destination.write(input.read());
        }
        input = input.add(1);
        destination = destination.wrapping_add(1);
    }

    #[cfg(target_os = "none")]
    let source_len = vector_size_elem4_alias_78e4(source.cast::<VectorBounds>()) as u32 as usize;
    output.add(1).write(allocation.wrapping_add(source_len) as usize as u32);
    output.add(2).write(allocation.wrapping_add(capacity) as usize as u32);
    output
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::VECTOR_WORD_COPY_CONSTRUCT, 0x1000).map(|slab| slab as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<(*mut u32, *mut u32, *mut u32)> {
        (*FIXTURE).map(|base| {
            let output = base as *mut u32;
            (output, output.add(0x20), output.add(0x80))
        })
    }

    #[test]
    fn copies_short_source_into_minimum_capacity_allocation() {
        let _fixture_lock = FIXTURE_LOCK.lock();
        let _heap = mock_heap();
        let Some((output, source, allocation)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("cxx/vector_word_copy_construct");
            return;
        };
        unsafe {
            source.write(source.add(3) as usize as u32);
            source.add(1).write(source.add(6) as usize as u32);
            source.add(2).write(source.add(9) as usize as u32);
            source.add(3).write(0x1111_1111);
            source.add(4).write(0x2222_2222);
            source.add(5).write(0x3333_3333);
            set_alloc_ret(allocation.cast());

            assert_eq!(vector_word_copy_construct(output, source), output);
            assert_eq!([allocation.read(), allocation.add(1).read(), allocation.add(2).read()], [0x1111_1111, 0x2222_2222, 0x3333_3333]);
            assert_eq!(output.read(), allocation as usize as u32);
            assert_eq!(output.add(1).read(), allocation.add(3) as usize as u32);
            assert_eq!(output.add(2).read(), allocation.add(32) as usize as u32);
        }
        assert_eq!(alloc_log(), (1, 128, 2));
    }

    #[test]
    fn preserves_source_length_above_minimum_capacity() {
        let _fixture_lock = FIXTURE_LOCK.lock();
        let _heap = mock_heap();
        let Some((output, source, allocation)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("cxx/vector_word_copy_construct");
            return;
        };
        unsafe {
            source.write(source.add(3) as usize as u32);
            source.add(1).write(source.add(36) as usize as u32);
            source.add(2).write(source.add(40) as usize as u32);
            for index in 0..33 {
                source.add(3 + index).write(index as u32 ^ 0xa5a5_0000);
            }
            set_alloc_ret(allocation.cast());

            vector_word_copy_construct(output, source);
            for index in 0..33 {
                assert_eq!(allocation.add(index).read(), index as u32 ^ 0xa5a5_0000);
            }
            assert_eq!(output.add(1).read(), allocation.add(33) as usize as u32);
            assert_eq!(output.add(2).read(), allocation.add(33) as usize as u32);
        }
        assert_eq!(alloc_log(), (1, 132, 2));
    }

    #[test]
    fn allocation_failure_skips_copy_but_retains_arm_null_based_bounds() {
        let _fixture_lock = FIXTURE_LOCK.lock();
        let _heap = mock_heap();
        let Some((output, source, _)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("cxx/vector_word_copy_construct");
            return;
        };
        unsafe {
            source.write(source.add(3) as usize as u32);
            source.add(1).write(source.add(4) as usize as u32);
            source.add(2).write(source.add(4) as usize as u32);
            source.add(3).write(0xfeed_face);
            output.write(u32::MAX);
            output.add(1).write(u32::MAX);
            output.add(2).write(u32::MAX);
            set_alloc_ret(core::ptr::null_mut());

            vector_word_copy_construct(output, source);
            assert_eq!(output.read(), 0);
            assert_eq!(output.add(1).read(), 4);
            assert_eq!(output.add(2).read(), 128);
        }
        assert_eq!(alloc_log(), (1, 128, 2));
    }
}
