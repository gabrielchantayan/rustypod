//! Heap telemetry ports — the per-allocation accounting retailOS keeps in
//! the app-heap descriptor (see `types.rs` for the 0x398-byte layout).
//!
//! - `heap_stats_add` — original: `FUN_0819d714` @ 0x0819d714 (160 bytes).
//!   Stamps the block header's telemetry halfwords (tag at +4, size class at
//!   +6), credits `bytes_per_tag[tag]` / `tag_total` (+0x30c) and
//!   `bytes_per_class[class]` / `class_total` (+0x220) with the block size,
//!   bumps `blocks_per_bin[log2_floor(size)]` (+0x310), raises the
//!   `peak_bytes` watermark (+0x394) to `tag_total` if that is higher, and
//!   bumps `bin_total` (+0x390).
//! - `heap_stats_sub` — original: `FUN_0819cd5c` @ 0x0819cd5c (136 bytes).
//!   The mirror image on a state change: debits the *passed* byte count from
//!   the tag/class counters recorded in the header, decrements the
//!   `log2_floor(size)` bin and `bin_total`, then tail-calls
//!   `heap_stats_add(heap, block, new_tag)` to re-credit the header's
//!   current size under the new tag (the peak watermark can only rise).
//! - `log2_floor` — original: `FUN_080e837c` @ 0x080e837c (52 bytes).
//!   floor(log2(x)) for a 32-bit word by 5-step binary search over a
//!   mask/shift table (ARMv5TE has no CLZ-emulating helper call here; the
//!   table is a `tst mask; lsrne value, shift; orrne result, shift` loop).
//!   `log2_floor(0) == 0`: no mask matches, the result accumulator stays 0
//!   (same result as `log2_floor(1)`).
//!
//! Deviations / unverifiable parts:
//!
//! - **size -> class mapping is UNVERIFIED.** The original calls the boot
//!   ROM at 0x22003eb0 through the literal veneer @ 0x08037e60
//!   (`ldr pc, [pc, #-4]`); the ROM is not part of osos.dec, so the true
//!   mapping cannot be recovered from the image. `size_to_class()` below
//!   implements a documented stand-in: classes are log2-spaced over 8-byte
//!   steps, i.e. `class = log2_floor(size / 8)` clamped to the descriptor's
//!   0..79 range (`NUM_CLASSES - 1`). For any 32-bit size this yields
//!   0..=28, so the clamp never fires — it only documents the contract.
//! - **log2_floor's table is absent from the image.** The literal pool word
//!   @ 0x080e83b4 points at 0x083e9b60, but osos.dec holds ADS library
//!   *code* there (`mov r0, r5; pop {r4, r5, r6, pc}` — the table bytes
//!   appear nowhere in the binary, so the pointer is presumably fixed up or
//!   the region repurposed at runtime). `LOG2_TABLE` below is the
//!   reconstructed canonical table; its content is forced by the algorithm
//!   (only these 5 masks + 5 shifts make the loop a correct floor-log2), so
//!   the port is behaviorally exact even though the bytes cannot be
//!   byte-compared against the binary.
//! - Out-of-range tag/class indices hit no bounds check, exactly like the
//!   original (which would silently corrupt neighboring counters); callers
//!   keep tags within 0..NUM_TAGS as the original's callers do.
//! - Counter arithmetic is wrapping, mirroring the original's unsigned
//!   32-bit adds/subs.

use crate::heap::types::{BlockHeader, HeapDescriptor, NUM_BINS, NUM_CLASSES, SIZE_MASK};

/// log2_floor lookup table: five bit masks tested from index 4 down to 0,
/// then the five matching shift amounts (single bits, so `|=` accumulates
/// the result). Original: 10 words @ 0x083e9b60 — see the header note;
/// these are the reconstructed canonical ADS values.
static LOG2_TABLE: [u32; 10] = [
    0xaaaaaaaa, 0xcccccccc, 0xf0f0f0f0, 0xff00ff00, 0xffff0000, // masks
    1, 2, 4, 8, 16, // shifts
];

/// log2_floor — original: `FUN_080e837c` @ 0x080e837c (52 bytes).
///
/// floor(log2(value)) via binary search: if any of the top 16 bits is set,
/// shift right by 16 and record 16, then likewise for the 8/4/2/1-bit
/// groupings. Returns 0 for `value == 0` (see header).
///
/// The table reads are volatile and the loop bound goes through
/// `black_box`: otherwise LLVM constant-folds the known table and unrolls
/// the loop into immediate compares, losing the original's rolled
/// `ldr`-from-table loop (behavior is identical either way).
/// `#[inline(never)]` keeps the original's `bl` call sites in
/// heap_stats_add / heap_stats_sub.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn log2_floor(mut value: u32) -> u32 {
    let masks = LOG2_TABLE.as_ptr();
    let shifts = LOG2_TABLE.as_ptr().add(5);
    let mut result: u32 = 0;
    let mut i: isize = core::hint::black_box(4);
    while i >= 0 {
        let mask = core::ptr::read_volatile(masks.offset(i));
        if mask & value != 0 {
            let shift = core::ptr::read_volatile(shifts.offset(i));
            value >>= shift;
            result |= shift;
        }
        i -= 1;
    }
    result
}

/// size -> telemetry class mapping. UNVERIFIED stand-in for the boot-ROM
/// routine @ 0x22003eb0 (reached through veneer 0x08037e60); see the module
/// header. log2-spaced over 8-byte steps, clamped to 0..NUM_CLASSES-1.
/// `#[inline(never)]` keeps the original's call-a-helper shape.
#[inline(never)]
pub fn size_to_class(size: u32) -> u32 {
    let units = size >> 3;
    let class = if units == 0 {
        0
    } else {
        31 - units.leading_zeros()
    };
    if class >= NUM_CLASSES as u32 {
        NUM_CLASSES as u32 - 1
    } else {
        class
    }
}

#[inline(always)]
unsafe fn credit(counter: *mut u32, amount: u32) {
    *counter = (*counter).wrapping_add(amount);
}

#[inline(always)]
unsafe fn debit(counter: *mut u32, amount: u32) {
    *counter = (*counter).wrapping_sub(amount);
}

/// heap_stats_add — original: `FUN_0819d714` @ 0x0819d714 (160 bytes).
///
/// Credit `block`'s size to the tag/class/bin counters and stamp the header
/// telemetry halfwords. `tag` indexes `bytes_per_tag` untruncated (as in the
/// original) but is stored as a halfword. `#[inline(never)]` preserves the
/// original's shape as the tail-call target of heap_stats_sub.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn heap_stats_add(
    heap: *mut HeapDescriptor,
    block: *mut BlockHeader,
    tag: u32,
) {
    let size = (*block).size_flags & SIZE_MASK;
    let class = size_to_class(size) as u16;
    // Header telemetry: tag halfword at +4, class halfword at +6 (the two
    // halves of BlockHeader.link_or_tag). Class store comes first, as in
    // the original.
    (block as *mut u16).add(3).write(class);
    (block as *mut u16).add(2).write(tag as u16);

    let heap = &mut *heap;
    credit(heap.bytes_per_tag.as_mut_ptr().add(tag as usize), size);
    heap.tag_total = heap.tag_total.wrapping_add(size);
    credit(
        heap.bytes_per_class.as_mut_ptr().add(class as usize),
        size,
    );
    heap.class_total = heap.class_total.wrapping_add(size);
    let bin = log2_floor(size) as usize;
    credit(heap.blocks_per_bin.as_mut_ptr().add(bin), 1);
    if heap.peak_bytes < heap.tag_total {
        heap.peak_bytes = heap.tag_total;
    }
    heap.bin_total = heap.bin_total.wrapping_add(1);
}

/// heap_stats_sub — original: `FUN_0819cd5c` @ 0x0819cd5c (136 bytes).
///
/// Debit `size` bytes from the tag/class recorded in `block`'s header and
/// from the `log2_floor(size)` bin, then re-credit the header's current
/// size under `new_tag` (the original tail-calls heap_stats_add).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn heap_stats_sub(
    heap: *mut HeapDescriptor,
    block: *mut BlockHeader,
    size: u32,
    new_tag: u32,
) {
    let old_tag = (block as *const u16).add(2).read() as usize; // +4
    let old_class = (block as *const u16).add(3).read() as usize; // +6

    let heap_ref = &mut *heap;
    debit(heap_ref.bytes_per_tag.as_mut_ptr().add(old_tag), size);
    heap_ref.tag_total = heap_ref.tag_total.wrapping_sub(size);
    debit(heap_ref.bytes_per_class.as_mut_ptr().add(old_class), size);
    heap_ref.class_total = heap_ref.class_total.wrapping_sub(size);
    let bin = log2_floor(size) as usize;
    debit(heap_ref.blocks_per_bin.as_mut_ptr().add(bin), 1);
    heap_ref.bin_total = heap_ref.bin_total.wrapping_sub(1);

    heap_stats_add(heap, block, new_tag);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::NUM_TAGS;
    use std::vec::Vec;

    fn zeroed_heap() -> HeapDescriptor {
        unsafe { core::mem::zeroed() }
    }

    fn header(size: u32) -> BlockHeader {
        BlockHeader {
            size_flags: size, // low flag bits clear: plain allocated size
            link_or_tag: 0,
        }
    }

    fn block_tag(block: &BlockHeader) -> u16 {
        unsafe { (block as *const BlockHeader as *const u16).add(2).read() }
    }

    fn block_class(block: &BlockHeader) -> u16 {
        unsafe { (block as *const BlockHeader as *const u16).add(3).read() }
    }

    /// Reference floor(log2): std's checked_ilog2; the original returns 0
    /// for 0 (where ilog2 is undefined), so map None -> 0.
    fn reference_log2(x: u32) -> u32 {
        x.checked_ilog2().unwrap_or(0)
    }

    #[test]
    fn log2_floor_matches_reference() {
        // Exhaustive low range.
        for x in 0u32..=1_000_000 {
            assert_eq!(unsafe { log2_floor(x) }, reference_log2(x), "x={x}");
        }
        // Powers of two and their neighbors across the full word.
        let mut cases: Vec<u32> = Vec::new();
        for bit in 0..32 {
            let p = 1u32 << bit;
            cases.extend_from_slice(&[p.wrapping_sub(1), p, p + 1]);
        }
        cases.extend_from_slice(&[0, u32::MAX, 0x8000_0000, 0xffff_0000, 0x3fff_fffc]);
        for x in cases {
            assert_eq!(unsafe { log2_floor(x) }, reference_log2(x), "x={x:#x}");
        }
    }

    #[test]
    fn log2_floor_of_zero_is_zero() {
        // No mask matches 0, so the result accumulator stays 0 — the same
        // value the function returns for 1 (std's ilog2 would panic on 0).
        assert_eq!(unsafe { log2_floor(0) }, 0);
        assert_eq!(unsafe { log2_floor(1) }, 0);
    }

    #[test]
    fn table_is_canonical_ads_values() {
        // The table is NOT present at 0x083e9b60 in osos.dec (that address
        // holds ADS library code; see module header), so a byte-compare
        // against the binary is impossible. Pin the reconstructed values:
        // the algorithm forces exactly these masks and shifts.
        assert_eq!(
            LOG2_TABLE,
            [
                0xaaaaaaaa, 0xcccccccc, 0xf0f0f0f0, 0xff00ff00, 0xffff0000, 1, 2, 4, 8, 16,
            ]
        );
        // And they must make log2_floor exact for every single-bit input.
        for bit in 0..32 {
            assert_eq!(unsafe { log2_floor(1 << bit) }, bit);
        }
    }

    #[test]
    fn add_credits_counters_and_stamps_header() {
        let mut heap = zeroed_heap();
        let mut block = header(128);
        unsafe { heap_stats_add(&mut heap, &mut block, 5) };

        assert_eq!(block_tag(&block), 5);
        assert_eq!(block_class(&block), size_to_class(128) as u16);
        assert_eq!(heap.bytes_per_tag[5], 128);
        assert_eq!(heap.tag_total, 128);
        assert_eq!(heap.bytes_per_class[size_to_class(128) as usize], 128);
        assert_eq!(heap.class_total, 128);
        assert_eq!(heap.blocks_per_bin[7], 1); // log2_floor(128) == 7
        assert_eq!(heap.bin_total, 1);
        assert_eq!(heap.peak_bytes, 128);
    }

    #[test]
    fn sub_debits_old_tag_and_recredits_new_tag() {
        let mut heap = zeroed_heap();
        let mut block = header(128);
        unsafe { heap_stats_add(&mut heap, &mut block, 5) };
        unsafe { heap_stats_sub(&mut heap, &mut block, 128, 9) };

        // Old tag fully debited, new tag credited; totals net to zero change.
        assert_eq!(heap.bytes_per_tag[5], 0);
        assert_eq!(heap.bytes_per_tag[9], 128);
        assert_eq!(heap.tag_total, 128);
        assert_eq!(heap.class_total, 128);
        assert_eq!(heap.bin_total, 1);
        assert_eq!(heap.blocks_per_bin[7], 1);
        assert_eq!(block_tag(&block), 9);
        assert_eq!(block_class(&block), size_to_class(128) as u16);
        // Watermark was already at 128 and cannot fall.
        assert_eq!(heap.peak_bytes, 128);
    }

    #[test]
    fn add_sub_cycle_is_symmetric_per_counter() {
        let mut heap = zeroed_heap();
        let mut blocks: Vec<BlockHeader> =
            [8, 16, 24, 64, 128, 1024, 4096].iter().map(|&s| header(s)).collect();

        // Credit every block under tag 3.
        for (i, b) in blocks.iter_mut().enumerate() {
            unsafe { heap_stats_add(&mut heap, b, 3 + i as u32 % 2) };
        }
        let snapshot = (heap.bytes_per_tag, heap.bytes_per_class, heap.blocks_per_bin);

        // Retag every block (same size out as in): per-tag/class/bin
        // counters must end up exactly where they started.
        for (i, b) in blocks.iter_mut().enumerate() {
            let tag = 3 + i as u32 % 2;
            let size = b.size_flags;
            unsafe { heap_stats_sub(&mut heap, b, size, tag) };
        }
        assert_eq!(heap.bytes_per_tag, snapshot.0);
        assert_eq!(heap.bytes_per_class, snapshot.1);
        assert_eq!(heap.blocks_per_bin, snapshot.2);
        assert_eq!(heap.bin_total, blocks.len() as u32);
        assert_eq!(heap.tag_total, blocks.iter().map(|b| b.size_flags).sum());
    }

    #[test]
    fn peak_watermark_tracks_running_max_and_never_falls() {
        let mut heap = zeroed_heap();
        let mut b1 = header(0x40);
        let mut b2 = header(0x400);
        let mut b3 = header(0x20);
        unsafe {
            heap_stats_add(&mut heap, &mut b1, 1);
            assert_eq!(heap.peak_bytes, 0x40);
            heap_stats_add(&mut heap, &mut b2, 1);
            assert_eq!(heap.peak_bytes, 0x440);
            heap_stats_add(&mut heap, &mut b3, 1);
            assert_eq!(heap.peak_bytes, 0x460);
            // Retag: totals unchanged, watermark stays.
            heap_stats_sub(&mut heap, &mut b2, 0x400, 2);
            assert_eq!(heap.tag_total, 0x460);
            assert_eq!(heap.peak_bytes, 0x460);
        }
    }

    #[test]
    fn bin_histogram_uses_log2_floor_of_size() {
        let mut heap = zeroed_heap();
        let sizes = [8u32, 15, 16, 17, 1024, 1025, 0x3fff_fffc];
        let mut blocks: Vec<BlockHeader> = sizes.iter().map(|&s| header(s)).collect();
        for b in blocks.iter_mut() {
            unsafe { heap_stats_add(&mut heap, b, 0) };
        }
        assert_eq!(heap.blocks_per_bin[3], 2); // 8, 15
        assert_eq!(heap.blocks_per_bin[4], 2); // 16, 17
        assert_eq!(heap.blocks_per_bin[10], 2); // 1024, 1025
        assert_eq!(heap.blocks_per_bin[29], 1); // 0x3fff_fffc
        assert_eq!(heap.bin_total, sizes.len() as u32);
        let total: u32 = heap.blocks_per_bin.iter().sum();
        assert_eq!(total, heap.bin_total);
    }

    #[test]
    fn size_to_class_is_log2_over_8_byte_steps() {
        // UNVERIFIED stand-in (see module header): pin the documented shape.
        assert_eq!(size_to_class(0), 0);
        assert_eq!(size_to_class(8), 0); // 1 unit
        assert_eq!(size_to_class(15), 0);
        assert_eq!(size_to_class(16), 1); // 2 units
        assert_eq!(size_to_class(1024), 7); // 128 units
        assert_eq!(size_to_class(0x3fff_fffc), 26);
        // Monotonic non-decreasing, always inside the descriptor's range.
        let mut prev = 0;
        for s in (0u32..=0x10_0000).step_by(8) {
            let c = size_to_class(s);
            assert!(c >= prev && (c as usize) < NUM_CLASSES);
            prev = c;
        }
        // Tag/class index ranges used by the stats functions.
        assert!(NUM_TAGS > 0 && NUM_BINS == 32);
    }
}
