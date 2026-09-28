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
/// dma_aligned_12byte_array_construct — original: `FUN_0839df4c` @
/// 0x0839df4c (132 bytes exactly, 0x0839df4c..0x0839dfd0; its matching
/// destructor begins immediately after). Raw A32 decoding finds two direct
/// inbound `bl` callers, both unconditional at 0x08104ea0 and 0x08104eb0,
/// with zero predicated forms. Its two direct calls are to already ported
/// `malloc_wrapper` and `dcache_clean_invalidate`.
///
/// Constructs a 12-byte-element [`DmaAlignedArray`]: clears its allocation and
/// aligned view, records `element_count`, allocates `element_count * 12 + 0x40`
/// bytes with `allocation_tag`, and aligns a successful block to 32 bytes.
/// Bit 27 clean-invalidates `element_count` units before bit 31 marks the
/// stored view as its uncached alias. A count-sized empty trivial-element
/// construction walk precedes `constructed = 1`.
///
/// Deliberate deviation: [`core::hint::black_box`] retains the otherwise empty
/// construction walk. It has no memory effect; the existing allocator and
/// cache-maintenance ports are called directly.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to writable target-size
/// [`DmaAlignedArray`] storage. Its successful allocation is owned by `array`.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.dma_aligned_12byte_array_construct")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_12byte_array_construct(
    array: *mut DmaAlignedArray,
    element_count: u32,
    allocation_tag: u32,
) -> *mut DmaAlignedArray {
    unsafe {
        (*array).allocation = 0;
        (*array).aligned_data = 0;
        (*array).element_count = element_count;
        (*array).constructed = 0;

        let allocation = crate::heap::veneers::malloc_wrapper(
            element_count
                .wrapping_mul(12)
                .wrapping_add(DMA_ALIGNED_ARRAY_ALLOCATION_HEADROOM) as usize,
            allocation_tag as usize,
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
                    element_count as usize,
                );
                (*array).aligned_data = aligned_data | DMA_ALIGNED_ARRAY_CACHE_ALIAS_BIT;
            }

            let mut index = 0u32;
            while index < element_count {
                core::hint::black_box(index);
                index = index.wrapping_add(1);
            }
            (*array).constructed = 1;
        }

        array
    }
}

/// dma_aligned_u32_array_construct — original: `FUN_0839e200` @
/// 0x0839e200 (128 bytes exactly, 0x0839e200..0x0839e280; the u32
/// destructor begins immediately after).
///
/// Raw A32 decoding finds exactly two direct inbound `bl` callers, both
/// unconditional (0x080fabc4 and 0x080fc404), with zero predicated `bl`
/// forms. Its two direct calls are to already ported `malloc_wrapper` and
/// `dcache_clean_invalidate`.
///
/// Constructs the u32-specialized [`DmaAlignedArray`]: clears allocation and
/// aligned view, records `element_count`, allocates `element_count * 4 + 0x40`
/// bytes with `allocation_tag`, then aligns a successful allocation to 32
/// bytes. Bit 27 clean-invalidates the element byte range before bit 31 marks
/// the stored view as its uncached alias. A count-sized empty trivial-element
/// construction walk precedes `constructed = 1`.
///
/// Deliberate deviation: [`core::hint::black_box`] retains the otherwise
/// empty count-dependent walk. It has no memory effect; the original's direct
/// calls are ordinary Rust calls to their existing ports.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to writable
/// [`DmaAlignedArray`] storage. Its successful allocation is owned by `array`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_u32_array_construct(
    array: *mut DmaAlignedArray,
    element_count: u32,
    allocation_tag: u32,
) -> *mut DmaAlignedArray {
    unsafe {
        (*array).allocation = 0;
        (*array).aligned_data = 0;
        (*array).element_count = element_count;
        (*array).constructed = 0;

        let allocation = crate::heap::veneers::malloc_wrapper(
            element_count
                .wrapping_mul(4)
                .wrapping_add(DMA_ALIGNED_ARRAY_ALLOCATION_HEADROOM) as usize,
            allocation_tag as usize,
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
                    element_count.wrapping_mul(4) as usize,
                );
                (*array).aligned_data = aligned_data | DMA_ALIGNED_ARRAY_CACHE_ALIAS_BIT;
            }

            let mut index = 0u32;
            while index < element_count {
                core::hint::black_box(index);
                index = index.wrapping_add(1);
            }
            (*array).constructed = 1;
        }

        array
    }
}

/// dma_aligned_u16_array_construct — original: `FUN_0839e2c8` @
/// 0x0839e2c8 (128 bytes exactly, 0x0839e2c8..0x0839e348; the next
/// separately linked function begins immediately after).
///
/// Raw decoding finds two direct `bl` callers, both unconditional
/// (0x081f4bdc and 0x081f4bf8), and no predicated `bl` forms. The body calls
/// already ported `malloc_wrapper` and `dcache_clean_invalidate`.
///
/// Constructs the u16-specialized sibling of [`DmaAlignedArray`]. It clears
/// allocation and aligned view, records `element_count`, allocates
/// `element_count * 2 + 0x40` bytes with the supplied tag, then aligns a
/// successful allocation up to 32 bytes. Bit 27 requests cache clean and
/// invalidate of the byte range before bit 31 marks the stored view as its
/// uncached alias. A count-sized empty trivial-element construction walk
/// precedes `constructed = 1`.
///
/// Deliberate deviation: [`core::hint::black_box`] retains the otherwise
/// empty count-dependent walk. It has no memory effect; the original's two
/// direct calls are ordinary Rust calls to their existing ports.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to writable
/// [`DmaAlignedArray`] storage. Its successful allocation is owned by `array`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_u16_array_construct(
    array: *mut DmaAlignedArray,
    element_count: u32,
    allocation_tag: u32,
) -> *mut DmaAlignedArray {
    unsafe {
        (*array).allocation = 0;
        (*array).aligned_data = 0;
        (*array).element_count = element_count;
        (*array).constructed = 0;

        let allocation = crate::heap::veneers::malloc_wrapper(
            element_count
                .wrapping_mul(2)
                .wrapping_add(DMA_ALIGNED_ARRAY_ALLOCATION_HEADROOM) as usize,
            allocation_tag as usize,
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
                    element_count.wrapping_mul(2) as usize,
                );
                (*array).aligned_data = aligned_data | DMA_ALIGNED_ARRAY_CACHE_ALIAS_BIT;
            }

            let mut index = 0u32;
            while index < element_count {
                core::hint::black_box(index);
                index = index.wrapping_add(1);
            }
            (*array).constructed = 1;
        }

        array
    }
}

/// dma_aligned_byte_array_construct_variant — original: `FUN_0839e018` @
/// 0x0839e018 (124 bytes exactly, 0x0839e018..0x0839e094; the destructor
/// opens immediately after). Five direct `bl` call sites, all unconditional:
/// 0x080f9d0c, 0x080fa8b0, 0x080fa9c8, 0x080fdf3c, and 0x080fe074. Raw
/// decoding of every ARM B/BL immediate in osos.dec finds no predicated forms
/// and no tail `b` entries.
///
/// A separately linked byte-array template instantiation with the same
/// algorithm as [`dma_aligned_byte_array_construct`]: clear allocation and
/// aligned-view words, retain `byte_count`, allocate `byte_count + 0x40` with
/// the supplied tag, and align a successful block to 32 bytes. Bit 27 causes a
/// cache clean+invalidate followed by the bit-31 uncached alias. It then
/// performs the byte-count-sized empty trivial-element loop before marking the
/// array constructed and returning `array`.
///
/// Deliberate deviation: [`core::hint::black_box`] preserves the empty loop;
/// it has no memory effect. The already ported `malloc_wrapper` and
/// `dcache_clean_invalidate` are direct calls, so no dispatch seam is added.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to writable
/// [`DmaAlignedArray`] storage. A successful allocation is owned by the array
/// and must later be released by its matching destructor.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.dma_aligned_byte_array_construct_variant")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_byte_array_construct_variant(
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

/// dma_aligned_12byte_array_destroy — original: `FUN_0839dfd0` @
/// 0x0839dfd0 (72 bytes exactly, 0x0839dfd0..0x0839e018; the next
/// separately linked constructor begins immediately after).
///
/// Raw A32 decoding finds two direct inbound `bl` callers, both plain and
/// unconditional at 0x08104f0c and 0x08104f14; there are no predicated inbound
/// `bl` forms. Its sole outbound call is predicated `blne free_wrapper` @
/// 0x080e7970 with tag 3.
///
/// This separately linked destructor accompanies the 12-byte-element
/// DMA-aligned array constructor at 0x0839df4c. If `constructed` is nonzero,
/// it makes the count-sized empty trivial-element destruction walk; it always
/// clears `constructed`, releases a non-NULL raw allocation through tag-3
/// [`free_wrapper`], and returns `array`. `aligned_data` and `element_count`
/// remain untouched.
///
/// Deliberate deviations: [`core::hint::black_box`] in the shared helper
/// retains the original empty loop, and the target-only link section prevents
/// LLVM from folding this separately hookable body into an identical
/// destructor.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to writable target-size
/// [`DmaAlignedArray`] storage. A nonzero `allocation` must be owned by this
/// object and valid for the retailOS tag-3 heap free path.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.dma_aligned_12byte_array_destroy")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_12byte_array_destroy(
    array: *mut DmaAlignedArray,
) -> *mut DmaAlignedArray {
    unsafe { dma_aligned_array_destroy_with_release(array, release_tag3_allocation) }
}

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

/// dma_aligned_byte_array_destroy_variant — original: `FUN_0839e094` @
/// 0x0839e094 (72 bytes exactly, 0x0839e094..0x0839e0dc; the next separately
/// linked function opens with `ldmib r1,{r1,r2}` immediately after).
/// Decoding every ARM B/BL word in `osos.dec` finds exactly four direct `bl`
/// call sites, all unconditional: 0x080fa798, 0x080faa64, 0x080faa78, and
/// 0x080fdfe0. The body itself contains a single predicated `blne` to
/// `free_wrapper` @ 0x080e7970 with tag 3 and no other call.
///
/// Separately linked destructor instance paired with
/// [`dma_aligned_byte_array_construct_variant`] @ 0x0839e018. Its algorithm
/// matches [`dma_aligned_array_destroy`] exactly: when `constructed` is
/// nonzero it performs the element-count-sized empty trivial-element walk,
/// unconditionally clears `constructed`, releases a non-NULL raw allocation
/// through `free_wrapper(ptr, 3)`, and returns `array`. `aligned_data` and
/// `element_count` are untouched.
///
/// Deliberate deviations: [`core::hint::black_box`] preserves the original's
/// count-dependent empty loop (no memory effect), and the target-only link
/// section keeps LLVM from folding this body into the identical primary
/// destructor so both hookable entries survive. The already ported
/// `free_wrapper` is reached through the same release helper as the primary
/// destructor, matching the original `blne` behavior.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to a writable target-size
/// [`DmaAlignedArray`]. A nonzero `allocation` must be owned by this object
/// and valid for the retailOS tag-3 heap free path.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.dma_aligned_byte_array_destroy_variant")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_byte_array_destroy_variant(
    array: *mut DmaAlignedArray,
) -> *mut DmaAlignedArray {
    unsafe { dma_aligned_array_destroy_with_release(array, release_tag3_allocation) }
}
/// dma_aligned_array_data_range_copy — original: `FUN_0839e0dc` @
/// 0x0839e0dc (12 bytes exactly, 0x0839e0dc..0x0839e0e8; the next separately
/// linked function starts with `push {r4,lr}`).
///
/// Raw words `e9910006 e8800006 e12fff1e` establish `ldmib r1,{r1,r2};
/// stmia r0,{r1,r2}; bx lr`. There are two direct plain `bl` callers
/// (0x080f9d34 and 0x080fdf48) and zero predicated `bl` forms; the body has
/// no calls. It reads the DMA-aligned array's aligned data view (+0x04) and
/// element count (+0x08) before storing them as a two-word output range, then
/// returns `output`.
///
/// Deliberate deviation: volatile accesses preserve the ARM's both-loads-
/// before-any-store ordering when `output` aliases `array`.
///
/// # Safety
///
/// `array` must be valid for aligned reads of its +0x04 and +0x08 words, and
/// `output` must be valid for two aligned `u32` writes. The ranges may overlap.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_array_data_range_copy(
    output: *mut u32,
    array: *const DmaAlignedArray,
) -> *mut u32 {
    let aligned_data = core::ptr::addr_of!((*array).aligned_data).read_volatile();
    let element_count = core::ptr::addr_of!((*array).element_count).read_volatile();
    output.write_volatile(aligned_data);
    output.add(1).write_volatile(element_count);
    output
}

/// dma_aligned_u32_array_destroy — original: `FUN_0839e280` @ 0x0839e280
/// (72 bytes exactly, 0x0839e280..0x0839e2c8; the u16 constructor begins
/// immediately after). Two direct inbound `bl` calls, at 0x080fab9c and
/// 0x080fc3d8, are unconditional; there are no predicated inbound calls. The
/// body contains one predicated `blne` to `free_wrapper` @ 0x080e7970 with
/// tag 3 and no other call.
///
/// Separately linked u32-specialized DMA-array destructor paired with the
/// constructor at 0x0839e200. If `constructed` is nonzero, it performs the
/// count-sized empty trivial-element destruction walk; it always clears that
/// byte, frees a non-NULL raw allocation through tag-3 `free_wrapper`, and
/// returns `array`. `aligned_data` and `element_count` remain untouched.
///
/// Deliberate deviations: [`core::hint::black_box`] retains the empty
/// count-dependent walk, and the target-only link section prevents LLVM from
/// folding this separately hookable body into an identical destructor.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to writable target-size
/// [`DmaAlignedArray`] storage. A nonzero `allocation` must be owned by this
/// object and valid for the retailOS tag-3 heap free path.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.dma_aligned_u32_array_destroy")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_u32_array_destroy(
    array: *mut DmaAlignedArray,
) -> *mut DmaAlignedArray {
    unsafe { dma_aligned_array_destroy_with_release(array, release_tag3_allocation) }
}
/// dma_aligned_array_destroy_variant_0839e1b8 — original: `FUN_0839e1b8` @
/// 0x0839e1b8 (72 bytes exactly, 0x0839e1b8..0x0839e200; the u32-array
/// constructor opens immediately after). Whole-image A32 decoding finds two
/// direct inbound `bl` callers, both unconditional (0x081c16fc, 0x081c1858),
/// and no predicated inbound `bl` form. Its sole outbound call is predicated
/// `blne free_wrapper` @ 0x080e7970 with tag 3.
///
/// A separately linked DMA-aligned-array destructor instance. If `constructed`
/// is nonzero, it makes the count-sized empty trivial-element destruction walk;
/// it always clears `constructed`, releases a non-NULL raw allocation through
/// tag-3 [`free_wrapper`], and returns `array`. `aligned_data` and
/// `element_count` remain untouched.
///
/// # Safety
///
/// `array` must be non-NULL, word-aligned, and point to writable target-size
/// [`DmaAlignedArray`] storage. A nonzero `allocation` must be owned by this
/// object and valid for the retailOS tag-3 heap free path.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.dma_aligned_array_destroy_variant_0839e1b8")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dma_aligned_array_destroy_variant_0839e1b8(
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
            let element_count = (*array).element_count;
            let mut index = 0u32;
            while index < element_count {
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
    fn variant_constructor_aligns_and_marks_uncached_alias() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(0x0800_1001usize as *mut u8);
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_byte_array_construct_variant(core::ptr::addr_of_mut!(array), 3, 7)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array), "returns this");
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x43, 7));
        assert_eq!(array.allocation, 0x0800_1001, "raw allocation at +0x00");
        assert_eq!(array.aligned_data, 0x8800_1020, "aligned uncached view at +0x04");
        assert_eq!(array.element_count, 3, "byte count at +0x08");
        assert_eq!(array.constructed, 1, "set after the trivial-element walk");
    }

    #[test]
    fn u16_constructor_allocates_two_bytes_per_element_and_marks_uncached_alias() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(0x0800_1001usize as *mut u8);
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_u16_array_construct(core::ptr::addr_of_mut!(array), 3, 7)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array), "returns this");
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x46, 7));
        assert_eq!(array.allocation, 0x0800_1001, "raw allocation at +0x00");
        assert_eq!(array.aligned_data, 0x8800_1020, "aligned uncached view at +0x04");
        assert_eq!(array.element_count, 3, "element count at +0x08");
        assert_eq!(array.constructed, 1, "set after the trivial-element walk");
    }
    #[test]
    fn u32_constructor_allocates_four_bytes_per_element_and_marks_uncached_alias() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(0x0800_1001usize as *mut u8);
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_u32_array_construct(core::ptr::addr_of_mut!(array), 3, 7)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array), "returns this");
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x4c, 7));
        assert_eq!(array.allocation, 0x0800_1001, "raw allocation at +0x00");
        assert_eq!(array.aligned_data, 0x8800_1020, "aligned uncached view at +0x04");
        assert_eq!(array.element_count, 3, "element count at +0x08");
        assert_eq!(array.constructed, 1, "set after the trivial-element walk");
    }

    #[test]
    fn u32_constructor_keeps_initial_state_when_allocation_fails() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(core::ptr::null_mut());
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_u32_array_construct(core::ptr::addr_of_mut!(array), 0, 3)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x40, 3));
        assert_eq!(array.allocation, 0, "the raw allocation store is unconditional");
        assert_eq!(array.aligned_data, 0, "no aligned view follows a NULL allocation");
        assert_eq!(array.element_count, 0);
        assert_eq!(array.constructed, 0, "the success byte remains clear");
    }


    #[test]
    fn u16_constructor_keeps_initial_state_when_allocation_fails() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(core::ptr::null_mut());
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_u16_array_construct(core::ptr::addr_of_mut!(array), 0, 3)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x40, 3));
        assert_eq!(array.allocation, 0, "the raw allocation store is unconditional");
        assert_eq!(array.aligned_data, 0, "no aligned view follows a NULL allocation");
        assert_eq!(array.element_count, 0);
        assert_eq!(array.constructed, 0, "the success byte remains clear");
    }

    #[test]
    fn variant_constructor_preserves_empty_state_when_allocation_fails() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(core::ptr::null_mut());
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_byte_array_construct_variant(core::ptr::addr_of_mut!(array), 0, 3)
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
    fn variant_destructor_walks_then_releases_tag3_allocation() {
        let mut array = DmaAlignedArray {
            allocation: 0x0821_0100,
            aligned_data: 0x8821_0120,
            element_count: 2,
            constructed: 1,
        };
        let before = array;
        RELEASE_CALLS.store(0, Ordering::SeqCst);
        RELEASED_ALLOCATION.store(0, Ordering::SeqCst);

        let result = unsafe { dma_aligned_byte_array_destroy_variant(&mut array) };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(array.allocation, before.allocation);
        assert_eq!(array.aligned_data, before.aligned_data);
        assert_eq!(array.element_count, before.element_count);
        assert_eq!(array.constructed, 0);
    }

    #[test]
    fn u32_destructor_frees_an_unconstructed_nonnull_allocation() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut array = DmaAlignedArray {
            allocation: 0x0821_0200,
            aligned_data: 0x8821_0220,
            element_count: u32::MAX,
            constructed: 0,
        };
        let before = array;

        let result = unsafe { dma_aligned_u32_array_destroy(&mut array) };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(array.allocation, before.allocation);
        assert_eq!(array.aligned_data, before.aligned_data);
        assert_eq!(array.element_count, before.element_count);
        assert_eq!(array.constructed, 0);
        assert_eq!(
            crate::heap::veneers::tests::free_log(),
            (1, before.allocation as usize as *mut u8, 3),
            "the construction byte only guards the empty walk, not the free"
        );
    }

    #[test]
    fn twelve_byte_destructor_frees_unconstructed_nonnull_allocation() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut array = DmaAlignedArray {
            allocation: 0x0821_0400,
            aligned_data: 0x8821_0420,
            element_count: u32::MAX,
            constructed: 0,
        };
        let before = array;

        let result = unsafe { dma_aligned_12byte_array_destroy(&mut array) };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(array.allocation, before.allocation);
        assert_eq!(array.aligned_data, before.aligned_data);
        assert_eq!(array.element_count, before.element_count);
        assert_eq!(array.constructed, 0);
        assert_eq!(
            crate::heap::veneers::tests::free_log(),
            (1, before.allocation as usize as *mut u8, 3),
            "the construction byte guards only the trivial-element walk"
        );
    }

    #[test]
    fn e1b8_variant_clears_construction_and_releases_tag3_allocation() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut array = DmaAlignedArray {
            allocation: 0x0821_0300,
            aligned_data: 0x8821_0320,
            element_count: 2,
            constructed: 1,
        };
        let before = array;

        let result = unsafe { dma_aligned_array_destroy_variant_0839e1b8(&mut array) };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(array.allocation, before.allocation);
        assert_eq!(array.aligned_data, before.aligned_data);
        assert_eq!(array.element_count, before.element_count);
        assert_eq!(array.constructed, 0);
        assert_eq!(
            crate::heap::veneers::tests::free_log(),
            (1, before.allocation as usize as *mut u8, 3),
        );
    }

    #[test]
    fn variant_destructor_with_release_walks_then_releases() {
        let mut array = DmaAlignedArray {
            allocation: 0x0821_0080,
            aligned_data: 0x8821_00a0,
            element_count: 5,
            constructed: 0xff,
        };
        let before = array;
        RELEASE_CALLS.store(0, Ordering::SeqCst);
        RELEASED_ALLOCATION.store(0, Ordering::SeqCst);

        let result = unsafe { dma_aligned_array_destroy_with_release(&mut array, record_release) };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(array.constructed, 0);
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
    #[test]
    fn data_range_copy_writes_view_and_count_and_returns_output() {
        let array = DmaAlignedArray {
            allocation: 0x0800_1000,
            aligned_data: 0x8800_1020,
            element_count: 0x10000,
            constructed: 1,
        };
        let mut output = [0, 0];

        let returned = unsafe {
            dma_aligned_array_data_range_copy(output.as_mut_ptr(), core::ptr::addr_of!(array))
        };

        assert_eq!(returned, output.as_mut_ptr());
        assert_eq!(output, [array.aligned_data, array.element_count]);
    }

    #[test]
    fn data_range_copy_loads_both_words_before_overlapping_output_stores() {
        let mut words = [0x0800_1000, 0x8800_1020, 0x10000, 0xdead_beef];
        let array = words.as_ptr() as *const DmaAlignedArray;

        let returned = unsafe { dma_aligned_array_data_range_copy(words.as_mut_ptr().add(2), array) };

        assert_eq!(returned, unsafe { words.as_mut_ptr().add(2) });
        assert_eq!(words, [0x0800_1000, 0x8800_1020, 0x8800_1020, 0x10000]);
    }
    #[test]
    fn twelve_byte_constructor_allocates_element_stride_and_marks_cache_alias() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(0x0800_1001usize as *mut u8);
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_12byte_array_construct(core::ptr::addr_of_mut!(array), 5, 3)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x7c, 3));
        assert_eq!(array.allocation, 0x0800_1001);
        assert_eq!(array.aligned_data, 0x8800_1020);
        assert_eq!(array.element_count, 5);
        assert_eq!(array.constructed, 1);
    }

    #[test]
    fn twelve_byte_constructor_retains_only_count_after_allocation_failure() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        crate::heap::veneers::tests::set_alloc_ret(core::ptr::null_mut());
        let mut array = DmaAlignedArray {
            allocation: 0xDEAD_BEEF,
            aligned_data: 0xDEAD_BEEF,
            element_count: 0xDEAD_BEEF,
            constructed: 0xff,
        };

        let result = unsafe {
            dma_aligned_12byte_array_construct(core::ptr::addr_of_mut!(array), 0, 0x2a)
        };

        assert_eq!(result, core::ptr::addr_of_mut!(array));
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x40, 0x2a));
        assert_eq!(array.allocation, 0);
        assert_eq!(array.aligned_data, 0);
        assert_eq!(array.element_count, 0);
        assert_eq!(array.constructed, 0);
    }
}
