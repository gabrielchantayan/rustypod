//! Port of the retailOS block-map context initializer at `0x080f8778` —
//! the routine that sets up the 0x20-byte context the fault-tolerant
//! resource parsers in the `0x080f8xxx` cluster operate on.
//!
//! The resource itself is a buffer of big-endian records (an indexed
//! record set: header byte at +8, big-endian entry count at +10, offset
//! table grown backwards from the end of the buffer) that was read from
//! storage in 512-byte blocks; `block_ok` carries one status byte per
//! block (0 = unreadable). The query/repair routines downstream
//! (`FUN_080f83fc`, `FUN_080f8454`, `FUN_080f84e0`, `FUN_080f824c`,
//! dispatched by `FUN_080f86c4`) use this context to drop or re-fetch
//! the entries that fall inside the bad blocks.

/// Parse/load context for a block-loaded big-endian record resource.
/// Layout matches the original struct word-for-word (0x20 bytes); the
/// caller's stack temp is 0x24 bytes but the original never touches the
/// last four.
#[repr(C)]
pub struct BlockMap {
    /// +0x00 — base of the record buffer.
    pub data: *mut u8,
    /// +0x04 — same buffer, viewed as the header (encoding byte at +8,
    /// big-endian entry-count halfword at +10). The original stores the
    /// `data` pointer here verbatim.
    pub header: *mut u8,
    /// +0x08 — native-endian descriptor: u16 total byte length at +0x1c,
    /// u16 max record size at +0x1e.
    pub desc: *const u8,
    /// +0x0c — number of 512-byte blocks the buffer spans
    /// (`*(u16 *)(desc + 0x1c) >> 9`).
    pub num_blocks: u32,
    /// +0x10 — per-block status bytes, 0 where a block failed to read.
    pub block_ok: *const u8,
    /// +0x14 — byte offset of the first bad block (`index << 9`),
    /// filled in later by the gap scanner. Initialized to 0.
    pub gap_start: u32,
    /// +0x18 — byte offset of the last bad block, filled in later.
    /// Initialized to 0.
    pub gap_end: u32,
    /// +0x1c — nonzero once the first block is known bad.
    pub first_bad: u8,
    /// +0x1d — nonzero once an interior block is known bad.
    pub mid_bad: u8,
    /// +0x1e — nonzero once the last block is known bad.
    pub last_bad: u8,
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed struct.
#[cfg(target_pointer_width = "32")]
const _BLOCK_MAP_SIZE: [u8; 0x20] = [0; core::mem::size_of::<BlockMap>()];
#[cfg(target_pointer_width = "32")]
const _HEADER_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(BlockMap, header)];
#[cfg(target_pointer_width = "32")]
const _DESC_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(BlockMap, desc)];
#[cfg(target_pointer_width = "32")]
const _NUM_BLOCKS_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(BlockMap, num_blocks)];
#[cfg(target_pointer_width = "32")]
const _BLOCK_OK_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(BlockMap, block_ok)];
#[cfg(target_pointer_width = "32")]
const _GAP_START_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(BlockMap, gap_start)];
#[cfg(target_pointer_width = "32")]
const _FIRST_BAD_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(BlockMap, first_bad)];
#[cfg(target_pointer_width = "32")]
const _LAST_BAD_OFFSET: [u8; 0x1e] = [0; core::mem::offset_of!(BlockMap, last_bad)];

/// block_map_init — original: `FUN_080f8778` @ 0x080f8778 (52 bytes,
/// one call site, in `FUN_080ed3f8` which builds the context on its
/// stack and immediately queries it with `FUN_080f86c4`).
///
/// Stores `data` at +0x00 and +0x04, `desc` at +0x08, derives
/// `num_blocks` at +0x0c as the native-endian u16 at `desc + 0x1c`
/// shifted right by 9 (byte length -> 512-byte block count), stores
/// `block_ok` at +0x10, and zeroes the gap range (+0x14/+0x18) and the
/// three bad-block flag bytes (+0x1c/+0x1d/+0x1e). A pure initializer —
/// no validation, no reads besides the descriptor halfword.
///
/// Deviations: none. The fields are written individually so the codegen
/// keeps the original's store sequence instead of a synthesized memcpy.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_map_init(
    ctx: *mut BlockMap,
    data: *mut u8,
    desc: *const u8,
    block_ok: *const u8,
) {
    let total_bytes = (desc.add(0x1c) as *const u16).read_unaligned() as u32;
    let ctx = &mut *ctx;
    ctx.data = data;
    ctx.header = data;
    ctx.desc = desc;
    ctx.num_blocks = total_bytes >> 9;
    ctx.block_ok = block_ok;
    ctx.gap_start = 0;
    ctx.gap_end = 0;
    ctx.first_bad = 0;
    ctx.mid_bad = 0;
    ctx.last_bad = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected field values, written straight from the Ghidra
    /// decompilation of the original.
    struct Expected {
        data: *mut u8,
        header: *mut u8,
        desc: *const u8,
        num_blocks: u32,
        block_ok: *const u8,
    }

    fn reference(data: *mut u8, desc: *const u8, block_ok: *const u8) -> Expected {
        let total_bytes = unsafe { (desc.add(0x1c) as *const u16).read_unaligned() } as u32;
        Expected {
            data,
            header: data, // mirrored verbatim
            desc,
            num_blocks: total_bytes >> 9,
            block_ok,
        }
    }

    fn run(data: *mut u8, desc: &[u8; 0x20], block_ok: *const u8) -> BlockMap {
        let mut ctx = BlockMap {
            data: 0xaaaa_aaaa as *mut u8,
            header: 0xbbbb_bbbb as *mut u8,
            desc: 0xcccc_cccc as *const u8,
            num_blocks: 0xdddd_dddd,
            block_ok: 0xeeee_eeee as *const u8,
            gap_start: 0x1111_1111,
            gap_end: 0x2222_2222,
            first_bad: 0x33,
            mid_bad: 0x44,
            last_bad: 0x55,
        };
        unsafe { block_map_init(&mut ctx, data, desc.as_ptr(), block_ok) };
        ctx
    }

    fn check(ctx: &BlockMap, want: &Expected) {
        assert_eq!(ctx.data, want.data);
        assert_eq!(ctx.header, want.header);
        assert_eq!(ctx.desc, want.desc);
        assert_eq!(ctx.num_blocks, want.num_blocks);
        assert_eq!(ctx.block_ok, want.block_ok);
        // Gap range and all three bad-block flags start cleared.
        assert_eq!(ctx.gap_start, 0);
        assert_eq!(ctx.gap_end, 0);
        assert_eq!(ctx.first_bad, 0);
        assert_eq!(ctx.mid_bad, 0);
        assert_eq!(ctx.last_bad, 0);
    }

    fn desc_with_len(total_bytes: u16) -> [u8; 0x20] {
        let mut desc = [0xcc_u8; 0x20];
        desc[0x1c..0x1e].copy_from_slice(&total_bytes.to_le_bytes());
        desc
    }

    #[test]
    fn stores_all_fields_and_zeroes_the_tail() {
        let desc = desc_with_len(0x2400);
        let data = 0x2200_1000 as *mut u8;
        let block_ok = 0x2200_2000 as *const u8;
        let ctx = run(data, &desc, block_ok);
        check(&ctx, &reference(data, desc.as_ptr(), block_ok));
    }

    #[test]
    fn data_pointer_is_mirrored_into_the_header_slot() {
        let desc = desc_with_len(0);
        let ctx = run(0x1234_5678 as *mut u8, &desc, 0x9abc_def0 as *const u8);
        assert_eq!(ctx.data, 0x1234_5678 as *mut u8);
        assert_eq!(ctx.header, 0x1234_5678 as *mut u8);
    }

    #[test]
    fn num_blocks_is_the_descriptor_halfword_shifted_right_by_9() {
        // Exact multiples, sub-block lengths that truncate, and the
        // u16 extremes.
        for (total, want) in [
            (0x0000u16, 0u32),
            (0x0001, 0),
            (0x01ff, 0),
            (0x0200, 1),
            (0x0201, 1),
            (0x03ff, 1),
            (0x0400, 2),
            (0x7fff, 0x3f),
            (0x8000, 0x40),
            (0xffff, 0x7f),
        ] {
            let desc = desc_with_len(total);
            let ctx = run(0x1000 as *mut u8, &desc, 0x2000 as *const u8);
            assert_eq!(ctx.num_blocks, want, "total_bytes={total:#06x}");
        }
    }

    #[test]
    fn matches_reference_over_a_pointer_and_length_corpus() {
        for total in [0x0000u16, 0x0200, 0x1234, 0xbe00, 0xffff] {
            for data in [0x0000_0000usize, 0x2200_0004, 0xffff_fffc] {
                for block_ok in [0x0000_0000usize, 0x2201_0000] {
                    let desc = desc_with_len(total);
                    let ctx = run(
                        data as *mut u8,
                        &desc,
                        block_ok as *const u8,
                    );
                    check(
                        &ctx,
                        &reference(
                            data as *mut u8,
                            desc.as_ptr(),
                            block_ok as *const u8,
                        ),
                    );
                }
            }
        }
    }
}
