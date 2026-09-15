//! Fixed-width register bitsets used by the code generator.

use super::heap::{cg_heap_alloc, CgHeap};

/// cg_register_bitset_create — original: `FUN_082c0c54` @ 0x082c0c54
/// (36 bytes, **5 plain `bl` + 0 predicated `bl` call sites**).
///
/// Allocates an eight-byte header followed by enough 32-bit words to hold one
/// bit per register, then stores `register_count` in header word zero. The
/// arena allocator zeroes the remaining header word and every bit word.
///
/// Deliberate deviations: the recovered bitset layout is represented by its
/// `u32` words rather than an opaque C record. The input is `u32` so its
/// `wrapping_add(31)` preserves the ARM `add` overflow behavior on host builds.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_register_bitset_create(
    heap: *mut CgHeap,
    register_count: u32,
) -> *mut u32 {
    let word_count = register_count.wrapping_add(31) >> 5;
    let bytes = word_count.wrapping_mul(4).wrapping_add(8) as usize;
    let bitset = cg_heap_alloc(heap, bytes) as *mut u32;
    bitset.write(register_count);
    bitset
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn allocates_rounded_bit_words_and_leaves_them_zeroed() {
        unsafe {
            let mut storage = [0xa5a5_a5a5u32; 16];
            let mut block = crate::codegen::heap::CgHeapBlock {
                next: core::ptr::null_mut(),
                base: storage.as_mut_ptr() as *mut u8,
                total: core::mem::size_of_val(&storage),
                current: 0,
            };
            let mut heap = CgHeap {
                current: &mut block,
                block_size: block.total,
            };

            for (register_count, expected_words) in [(0, 0), (1, 1), (32, 1), (33, 2)] {
                let bitset = cg_register_bitset_create(&mut heap, register_count);
                assert_eq!(bitset.read(), register_count);
                assert_eq!(bitset.add(1).read(), 0, "header spare word");
                for word in 0..expected_words {
                    assert_eq!(bitset.add(2 + word).read(), 0, "register {register_count}, word {word}");
                }
            }
            assert_eq!(block.current, 8 + 16 + 16 + 16);
        }
    }
}
