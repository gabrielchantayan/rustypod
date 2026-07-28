//! The tag-57 *tracked* allocator's free side — 32-byte-aligned blocks
//! with a size cookie and a running byte counter. Cluster
//! 0x083906f4..0x08390774 plus the tag-57 veneers @ 0x08391d24/0x08391d2c.
//!
//! Block layout produced by the allocator @ 0x08390b8c (not ported here,
//! but decoded to recover the layout — see below):
//!
//! ```text
//! raw + 0x00  i32   size          bytes the caller asked for
//! raw + 0x04  i32   size >> 31    sign extension, so the pair is an i64
//! raw + 0x08        base          first byte of the payload area
//! ...               padding       so that `data` lands 32-byte aligned
//! data - 0x04 u32   pad           data - base, recovered on free
//! data              payload
//! ```
//!
//! The allocator computes `data = (base + 36) & ~31`, i.e. at least 4 and
//! at most 36 bytes of padding — the +4 guarantees room for the `pad`
//! word itself.
//!
//! Accounting globals live in the 0x08adc2c0 block (9 code references):
//!
//! ```text
//! +0x38  i64  current_bytes   incremented on alloc, decremented on free
//! +0x40  i64  peak_bytes      raised to current_bytes whenever it grows
//! ```
//!
//! Both are read/written with `ldrd`/`strd`, so the block is 8-aligned
//! (0x08adc2f8 and 0x08adc300 are). The peak is only touched by the
//! allocator and by the reset helper @ 0x08390c30; the free path here
//! just subtracts, and it subtracts a *signed* 32-bit size widened to 64
//! (`sbc r1, r1, r2, asr #31`).
//!
//! Ported here (binary-scanned call counts):
//!
//! - `tracked_free` — original: `FUN_083906f4` @ 0x083906f4 (68 bytes:
//!   64 code + the 0x08adc2c0 literal; **218 `bl` + 22 tail `b` call
//!   sites**). Undoes the layout above and hands the raw block to the
//!   tag-57 free veneer.
//! - `tracked_free_pointer_array` — original: `FUN_08390734` @ 0x08390734
//!   (68 bytes, 3 call sites). Frees a block that starts with a word
//!   count and continues with `count - 1` pointers, releasing each
//!   non-NULL element with `tracked_free` before releasing the block.
//! - `free_tag57` / `alloc_tag57` — originals @ 0x08391d24 and
//!   0x08391d2c (8 bytes each): `mov r1, #57` in front of `free_wrapper`
//!   @ 0x080e7970 / `malloc_wrapper` @ 0x080eb67c (heap/veneers.rs).
//!
//! Simplification, same as `heap/veneers.rs` makes for the default heap:
//! the accounting block is a `static` here instead of living at
//! 0x08adc2c0.
//!
//! Word-index rule: every field `tracked_free` touches is a 32-bit
//! scalar, so its literal byte offsets are correct on a 64-bit host too.
//! The pointer array is different — its cookie and elements are
//! pointer-sized, so it is addressed by *index* through a `*mut *mut u8`,
//! which is stride 4 on the target and stride 8 on the host.

use crate::heap::veneers::{free_wrapper, malloc_wrapper};

/// Caller tag this allocator uses for both halves (`mov r1, #57`).
pub const TAG_TRACKED: usize = 57;

/// Bytes of header below the payload area (`size`, `size >> 31`).
pub const BLOCK_HEADER_SIZE: usize = 8;

/// Allocation accounting block. Original: 0x08adc2c0; only the two
/// counters this module and the allocator touch are named.
#[repr(C)]
pub struct AllocStats {
    /// 0x00..0x38 — fields owned by other parts of the allocator.
    pub reserved: [u32; 14],
    /// +0x38: bytes currently outstanding.
    pub current_bytes: i64,
    /// +0x40: high-water mark of `current_bytes`.
    pub peak_bytes: i64,
}

/// The accounting block (original @ 0x08adc2c0).
pub static mut ALLOC_STATS: AllocStats = AllocStats {
    reserved: [0; 14],
    current_bytes: 0,
    peak_bytes: 0,
};

/// alloc_tag57 — original @ 0x08391d2c (8 bytes): `malloc_wrapper` with
/// caller tag 57.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn alloc_tag57(size: usize) -> *mut u8 {
    malloc_wrapper(size, TAG_TRACKED)
}

/// free_tag57 — original @ 0x08391d24 (8 bytes): `free_wrapper` with
/// caller tag 57.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn free_tag57(block: *mut u8) {
    free_wrapper(block, TAG_TRACKED)
}

/// tracked_free — original @ 0x083906f4.
///
/// Recovers the raw block from an aligned payload pointer, subtracts the
/// recorded size from the running byte counter, and releases the block
/// with caller tag 57. NULL is ignored.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_free(payload: *mut u8) {
    if payload.is_null() {
        return;
    }
    let pad = (payload.sub(4) as *const u32).read() as usize;
    let base = payload.sub(pad);
    let block = base.sub(BLOCK_HEADER_SIZE);
    let size = (block as *const i32).read();
    let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
    (*stats).current_bytes = (*stats).current_bytes.wrapping_sub(size as i64);
    free_tag57(block);
}

/// tracked_free_pointer_array — original @ 0x08390734.
///
/// The block starts one word below `elements` with a *word count*; the
/// remaining `count - 1` words are pointers to tracked blocks. Frees each
/// non-NULL element, then the block itself. NULL is ignored.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_free_pointer_array(elements: *mut *mut u8) {
    if elements.is_null() {
        return;
    }
    let base = elements.sub(1);
    let count = (base as *const usize).read();
    let mut index = 1usize;
    while index < count {
        let element = base.add(index).read();
        if !element.is_null() {
            tracked_free(element);
        }
        index += 1;
    }
    tracked_free(base as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::MutexGuard;

    const ARENA_SIZE: usize = 4096;

    #[repr(C, align(32))]
    struct Arena([u8; ARENA_SIZE]);

    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;
    static mut FREED: [*mut u8; 16] = [core::ptr::null_mut(); 16];
    static mut FREE_TAGS: [usize; 16] = [0; 16];
    static mut FREE_COUNT: usize = 0;

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = ARENA_USED;
        let aligned = (size + 31) & !31;
        if used + aligned > ARENA_SIZE {
            return core::ptr::null_mut();
        }
        ARENA_USED = used + aligned;
        core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        if FREE_COUNT < 16 {
            FREED[FREE_COUNT] = ptr;
            FREE_TAGS[FREE_COUNT] = tag;
            FREE_COUNT += 1;
        }
    }

    unsafe extern "C" fn arena_create(
        desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        desc as *mut HeapDescriptorDescriptor
    }

    /// One guard per test function — a second, shadowed guard would
    /// self-deadlock on the same mutex.
    fn arena() -> MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            ARENA_USED = 0;
            FREE_COUNT = 0;
            FREED = [core::ptr::null_mut(); 16];
            FREE_TAGS = [0; 16];
            ALLOC_STATS.current_bytes = 0;
            ALLOC_STATS.peak_bytes = 0;
            let ops = core::ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = arena_alloc;
            (*ops).free = arena_free;
            (*ops).create = arena_create;
        }
        guard
    }

    unsafe fn freed() -> &'static [*mut u8] {
        let count = core::ptr::read(core::ptr::addr_of!(FREE_COUNT));
        core::slice::from_raw_parts(core::ptr::addr_of!(FREED).cast::<*mut u8>(), count)
    }

    /// Builds a tracked block exactly the way the allocator @ 0x08390b8c
    /// does, and returns (raw block, payload).
    /// `size` is only the recorded cookie; the arena always hands out a
    /// fixed 160 bytes so a negative cookie can be tested too.
    unsafe fn make_block(size: i32) -> (*mut u8, *mut u8) {
        let raw = arena_alloc(core::ptr::null_mut(), 160, TAG_TRACKED);
        assert!(!raw.is_null());
        (raw as *mut i32).write(size);
        (raw.add(4) as *mut i32).write(size >> 31);
        let base = raw.add(BLOCK_HEADER_SIZE);
        let payload = ((base as usize + 36) & !31) as *mut u8;
        (payload.sub(4) as *mut u32).write((payload as usize - base as usize) as u32);
        (raw, payload)
    }

    #[test]
    fn null_is_ignored() {
        let _guard = arena();
        unsafe {
            tracked_free(core::ptr::null_mut());
            tracked_free_pointer_array(core::ptr::null_mut());
            assert!(freed().is_empty());
            assert_eq!(ALLOC_STATS.current_bytes, 0);
        }
    }

    #[test]
    fn frees_the_raw_block_with_tag_fifty_seven() {
        let _guard = arena();
        unsafe {
            let (raw, payload) = make_block(100);
            ALLOC_STATS.current_bytes = 500;
            tracked_free(payload);
            assert_eq!(freed(), &[raw]);
            assert_eq!(FREE_TAGS[0], 57);
            assert_eq!(ALLOC_STATS.current_bytes, 400);
        }
    }

    /// The payload is 32-byte aligned and the padding is 4..=36 bytes, so
    /// the pad word always fits below it. Sweep every raw alignment the
    /// arena can produce.
    #[test]
    fn recovers_the_block_at_every_alignment() {
        let _guard = arena();
        unsafe {
            for skew in 0..8usize {
                ARENA_USED = skew * 4;
                let (raw, payload) = make_block(8);
                assert_eq!(payload as usize % 32, 0, "payload must be 32-aligned");
                let pad = payload as usize - (raw as usize + BLOCK_HEADER_SIZE);
                assert!((4..=36).contains(&pad), "pad={pad}");
                FREE_COUNT = 0;
                tracked_free(payload);
                assert_eq!(freed(), &[raw], "skew={skew}");
            }
        }
    }

    /// The size cookie is signed and widened to 64 bits
    /// (`sbc r1, r1, r2, asr #31`), so a negative cookie *raises* the
    /// counter.
    #[test]
    fn the_size_cookie_is_signed() {
        let _guard = arena();
        unsafe {
            let (_, payload) = make_block(-16);
            ALLOC_STATS.current_bytes = 0;
            tracked_free(payload);
            assert_eq!(ALLOC_STATS.current_bytes, 16);
        }
    }

    /// The subtraction borrows across the 32-bit boundary.
    #[test]
    fn the_counter_is_a_full_sixty_four_bit_subtract() {
        let _guard = arena();
        unsafe {
            let (_, payload) = make_block(1);
            ALLOC_STATS.current_bytes = 0x1_0000_0000;
            tracked_free(payload);
            assert_eq!(ALLOC_STATS.current_bytes, 0xffff_ffff);
        }
    }

    #[test]
    fn the_pointer_array_frees_every_element_then_itself() {
        let _guard = arena();
        unsafe {
            // Three tracked payloads, one NULL slot, then the array.
            let (raw_a, pay_a) = make_block(10);
            let (raw_b, pay_b) = make_block(20);
            let (raw_c, pay_c) = make_block(30);
            let (array_raw, array_payload) = make_block(64);
            let base = array_payload as *mut *mut u8;
            // base[0] = word count, base[1..] = elements.
            (base as *mut usize).write(5);
            base.add(1).write(pay_a);
            base.add(2).write(core::ptr::null_mut());
            base.add(3).write(pay_b);
            base.add(4).write(pay_c);

            ALLOC_STATS.current_bytes = 1000;
            tracked_free_pointer_array(base.add(1));

            // 10 + 20 + 30 + 64 subtracted; NULL slot skipped.
            assert_eq!(ALLOC_STATS.current_bytes, 1000 - 124);
            assert_eq!(freed(), &[raw_a, raw_b, raw_c, array_raw]);
        }
    }

    /// A count of 1 (or 0) means no elements — only the block is freed.
    #[test]
    fn an_empty_pointer_array_frees_only_itself() {
        let _guard = arena();
        unsafe {
            let (array_raw, array_payload) = make_block(16);
            let base = array_payload as *mut *mut u8;
            (base as *mut usize).write(1);
            tracked_free_pointer_array(base.add(1));
            assert_eq!(freed(), &[array_raw]);
        }
    }
}
