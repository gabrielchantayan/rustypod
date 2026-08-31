//! `dma_aligned_array_destroy` — original: `FUN_0839e164` @ 0x0839e164
//! (72 bytes; 26 `bl` call sites, all unconditional).
//!
//! Raw ARM establishes the exact extent `0x0839e164..0x0839e1ac`: the next
//! separately linked function starts with `ldmib r1,{r1,r2}` at 0x0839e1ac.
//! Decoding every ARM B/BL word in `osos.dec` finds the 26 direct `bl` sites,
//! no predicated forms, and no tail `b`; 0x0839e164 appears in no data word,
//! so this is a statically-bound destructor rather than a virtual target.
//!
//! The object owns a raw tag-3 allocation at +0x00. Its +0x04 field is the
//! 32-byte-aligned view (possibly with the constructor's high-bit cache flag),
//! +0x08 is the element count, and +0x0c records successful construction.
//! When constructed, retailOS performs a count-sized empty destruction walk;
//! it then clears the construction byte, conditionally frees the raw allocation
//! through `free_wrapper(ptr, 3)`, and returns `this`. The walk has no element
//! destructor call because this template instantiation's elements are trivial.
//!
//! Deliberate codegen deviation: `black_box` preserves the count-dependent
//! busy-wait rather than letting LLVM erase the otherwise empty Rust loop. It
//! has no memory effect; all object reads, the construction-byte clear, the
//! non-NULL free guard, and the tag-3 release match the raw body.

use crate::heap::veneers::free_wrapper;

const DMA_ALIGNED_ARRAY_FREE_TAG: usize = 3;

const DMA_ALIGNED_ARRAY_ALIGNMENT: u32 = 0x20;
const DMA_ALIGNED_ARRAY_ALLOCATION_HEADROOM: u32 = 0x40;
const DMA_ALIGNED_ARRAY_CACHE_ALIAS_BIT: u32 = 0x8000_0000;
const DMA_ALIGNED_ARRAY_CACHE_FLUSH_REGION_BIT: u32 = 0x0800_0000;

/// dma_aligned_byte_array_construct — original: `FUN_0839e0e8` @
/// 0x0839e0e8 (124 bytes exactly, 0x0839e0e8..0x0839e164; the destructor
/// opens immediately after). 26 direct `bl` call sites, all unconditional;
/// zero predicated `bl` forms and zero tail `b` sites, verified by decoding
/// every ARM B/BL word in `osos.dec`.
///
/// Constructs the byte-specialized sibling of [`DmaAlignedArray`]:
///
/// ```text
/// allocation = malloc_wrapper(byte_count + 0x40, tag)
/// array.allocation = allocation
/// if allocation != 0:
///     aligned = (allocation + 0x1f) & !0x1f
///     array.aligned_data = aligned
///     if aligned & 0x0800_0000:
///         dcache_clean_invalidate(aligned, byte_count)
///         array.aligned_data |= 0x8000_0000
///     repeat byte_count times: empty trivial-element construction
///     array.constructed = 1
/// return array
/// ```
///
/// `allocation`, `aligned_data`, and `element_count` are first seeded to
/// zero, zero, and `byte_count`; `constructed` starts at zero. The allocation
/// headroom retains `byte_count` usable bytes after the 32-byte align-up.
/// The bit-27 path makes the cleaned aligned view an uncached-alias pointer
/// by setting bit 31, exactly as the ARM stores it.
///
/// Deliberate deviation: [`core::hint::black_box`] keeps the original's
/// count-dependent empty loop from disappearing during optimization. It has
/// no memory effect. The calls to already ported `malloc_wrapper` and
/// `dcache_clean_invalidate` are direct rather than the original `bl`
/// instructions, preserving their observable behavior.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to writable
/// `DmaAlignedArray` storage. A successful allocation is owned by the array
/// and must later be released by [`dma_aligned_array_destroy`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_byte_array_construct(
    array: *mut DmaAlignedArray,
    byte_count: u32,
    tag: u32,
) -> *mut DmaAlignedArray {
    unsafe {
        (*array).allocation = 0;
        (*array).aligned_data = 0;
        (*array).element_count = byte_count;
        (*array).constructed = 0;

        let allocation = crate::heap::veneers::malloc_wrapper(
            byte_count.wrapping_add(DMA_ALIGNED_ARRAY_ALLOCATION_HEADROOM) as usize,
            tag as usize,
        ) as usize as u32;
        (*array).allocation = allocation;

        if allocation != 0 {
            let aligned_data = allocation
                .wrapping_add(DMA_ALIGNED_ARRAY_ALIGNMENT - 1)
                & !(DMA_ALIGNED_ARRAY_ALIGNMENT - 1);
            (*array).aligned_data = aligned_data;

            if aligned_data & DMA_ALIGNED_ARRAY_CACHE_FLUSH_REGION_BIT != 0 {
                crate::heap::dcache::dcache_clean_invalidate(
                    aligned_data as usize as *mut u8,
                    byte_count as usize,
                );
                (*array).aligned_data = aligned_data | DMA_ALIGNED_ARRAY_CACHE_ALIAS_BIT;
            }

            let mut index = 0u32;
            while index < byte_count {
                core::hint::black_box(index);
                index = index.wrapping_add(1);
            }
            (*array).constructed = 1;
        }

        array
    }
}

/// ARM-layout descriptor for the trivially destructible DMA-aligned array.
///
/// Pointer-shaped fields remain `u32`: retailOS addresses are 32 bits even
/// when host tests execute with 64-bit pointers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DmaAlignedArray {
    /// Raw tag-3 allocation, released by this destructor when nonzero.
    pub allocation: u32,
    /// 32-byte-aligned view into `allocation`; not touched by destruction.
    pub aligned_data: u32,
    /// Number of trivial elements in the count-sized destruction walk.
    pub element_count: u32,
    /// Nonzero after successful construction; cleared on every destruction.
    pub constructed: u8,
}

type ReleaseAllocation = unsafe extern "C" fn(*mut u8);

/// dma_aligned_array_destroy — original: `FUN_0839e164` @ 0x0839e164
/// (72 bytes; 26 unconditional `bl` call sites, zero tail branches).
///
/// Performs the trivial-element destruction walk when `constructed` is
/// nonzero, clears that byte, releases a non-NULL raw allocation through the
/// tag-3 heap path, and returns `array`. `aligned_data` and `element_count`
/// are retained exactly as the ARM body does.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to a writable target-size
/// `DmaAlignedArray`. A nonzero `allocation` must be owned by this object and
/// valid for the retailOS tag-3 heap free path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_array_destroy(
    array: *mut DmaAlignedArray,
) -> *mut DmaAlignedArray {
    unsafe { dma_aligned_array_destroy_with_release(array, release_tag3_allocation) }
}

unsafe extern "C" fn release_tag3_allocation(allocation: *mut u8) {
    unsafe { free_wrapper(allocation, DMA_ALIGNED_ARRAY_FREE_TAG) };
}

#[inline(always)]
unsafe fn dma_aligned_array_destroy_with_release(
    array: *mut DmaAlignedArray,
    release: ReleaseAllocation,
) -> *mut DmaAlignedArray {
    unsafe {
        if (*array).constructed != 0 {
            let mut index = 0u32;
            while index < (*array).element_count {
                let _ = core::hint::black_box(index);
                index = index.wrapping_add(1);
            }
        }

        (*array).constructed = 0;
        let allocation = (*array).allocation;
        if allocation != 0 {
            release(allocation as usize as *mut u8);
        }
        array
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_ALLOCATION: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(allocation: *mut u8) {
        RELEASE_CALLS.fetch_add(1, Ordering::SeqCst);
        RELEASED_ALLOCATION.store(allocation as usize, Ordering::SeqCst);
    }

    #[test]
    fn byte_constructor_aligns_flushes_and_marks_the_cache_alias() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(0x0800_1001usize as *mut u8);
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_byte_array_construct(core::ptr::addr_of_mut!(array), 3, 7)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array), "returns this");
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x43, 7));
        assert_eq!(array.allocation, 0x0800_1001, "raw allocation at +0x00");
        assert_eq!(
            array.aligned_data,
            0x8800_1020,
            "bit-27 allocations are aligned, cache-cleaned, and marked as uncached aliases"
        );
        assert_eq!(array.element_count, 3, "byte count at +0x08");
        assert_eq!(array.constructed, 1, "set only after the trivial-element walk");
    }

    #[test]
    fn byte_constructor_preserves_empty_state_when_allocation_fails() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(core::ptr::null_mut());
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_byte_array_construct(core::ptr::addr_of_mut!(array), 0, 3)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x40, 3));
        assert_eq!(array.allocation, 0, "the raw allocation store is unconditional");
        assert_eq!(array.aligned_data, 0, "no aligned view follows a NULL allocation");
        assert_eq!(array.element_count, 0);
        assert_eq!(array.constructed, 0, "the success byte remains clear");
    }

    #[test]
    fn constructed_array_walks_then_releases_raw_allocation() {
        let mut array = DmaAlignedArray {
            allocation: 0x0821_0020,
            aligned_data: 0x8821_0040,
            element_count: 3,
            constructed: 0xff,
        };
        let before = array;
        RELEASE_CALLS.store(0, Ordering::SeqCst);
        RELEASED_ALLOCATION.store(0, Ordering::SeqCst);

        let result = unsafe { dma_aligned_array_destroy_with_release(&mut array, record_release) };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(array.allocation, before.allocation, "raw allocation remains installed");
        assert_eq!(array.aligned_data, before.aligned_data, "aligned view is untouched");
        assert_eq!(array.element_count, before.element_count, "element count is untouched");
        assert_eq!(array.constructed, 0, "construction state is always cleared");
        assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASED_ALLOCATION.load(Ordering::SeqCst), before.allocation as usize);
    }

    #[test]
    fn empty_unconstructed_array_skips_release_but_still_returns_this() {
        let mut array = DmaAlignedArray {
            allocation: 0,
            aligned_data: 0x8000_0040,
            element_count: 0,
            constructed: 0,
        };
        let before = array;
        RELEASE_CALLS.store(0, Ordering::SeqCst);
        RELEASED_ALLOCATION.store(0, Ordering::SeqCst);

        let result = unsafe { dma_aligned_array_destroy_with_release(&mut array, record_release) };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(array.allocation, before.allocation);
        assert_eq!(array.aligned_data, before.aligned_data);
        assert_eq!(array.element_count, before.element_count);
        assert_eq!(array.constructed, 0);
        assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(RELEASED_ALLOCATION.load(Ordering::SeqCst), 0);
    }
}
