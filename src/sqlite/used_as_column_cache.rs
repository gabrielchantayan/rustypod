//! The column-cache register-range query — SQLite 3.5.9's
//! `usedAsColumnCache` (expr.c).
//!
//! `used_as_column_cache` — original: `FUN_083966a0` @ 0x083966a0 (64
//! bytes; 3 `bl` call sites, binary-scanned, no tail `b` sites:
//! 0x083774dc in FUN_08376ef0, 0x0837a380 in FUN_0837a354 —
//! `sqlite3GetTempRange`, probing `iRangeReg..iRangeReg+nRangeReg-1` —
//! and 0x0837a3e8 in `get_temp_reg` @ 0x0837a3bc
//! ([`crate::sqlite::get_temp_reg`]), which discards the verdict).
//!
//! Upstream 3.5.9 (expr.c, verbatim):
//!
//! ```c
//! static int usedAsColumnCache(Parse *pParse, int iFrom, int iTo){
//!   int i;
//!   for(i=0; i<pParse->nColCache; i++){
//!     int r = pParse->aColCache[i].iReg;
//!     if( r>=iFrom && r<=iTo ) return 1;
//!   }
//!   return 0;
//! }
//! ```
//!
//! Algorithm (verified against osos.asm 0x083966a0..0x083966e0): load
//! `nColCache` ONCE at entry (`ldr lr,[r0,#0x58]`; the count lives in
//! `lr` for the whole scan), walk the fixed-size `aColCache` records,
//! and return 1 on the first record whose `iReg` lies inside the
//! INCLUSIVE range `[start, end]`, else 0. All comparisons are signed
//! (`blt`, `movle`, loop head `bgt`), so a negative `nColCache` scans
//! nothing — same as an empty cache.
//!
//! `Parse`/`ColCache` fields used (fixed-width, host-independent):
//!
//! ```text
//! +0x58 nColCache  (i32)     records in use — loaded once at entry
//! +0x60 aColCache  (16-byte records)
//!        record +0x0c iReg (i32)  the cached column's VDBE register
//! ```
//!
//! Deviations: none against upstream 3.5.9. Later SQLite versions test
//! `iReg != 0` first; 3.5.9 does not, and neither does the firmware (no
//! zero test anywhere in the 16 instructions) — register 0 inside the
//! range IS a hit. The `parse` parameter is `*mut u8` only so the
//! exported symbol drops straight into the `TempRegOps` seam in
//! [`crate::sqlite::get_temp_reg`]; the function performs no stores.

/// Byte offset of `Parse.nColCache` (original: `ldr lr,[r0,#0x58]` at
/// entry; the count is never re-read during the scan).
pub const N_COL_CACHE_OFFSET: usize = 0x58;

/// Byte offset of `Parse.aColCache` (original: the record base is formed
/// as `add r12,r0,r3, lsl #0x4` and then `ldr r12,[r12,#0x6c]`, i.e.
/// array base 0x60 + record index * 0x10).
pub const A_COL_CACHE_OFFSET: usize = 0x60;

/// Byte size of one `ColCache` record (original: the `lsl #0x4` scale
/// on the record index).
pub const COL_CACHE_RECORD_SIZE: usize = 0x10;

/// Record-relative byte offset of `ColCache.iReg` (original:
/// `ldr r12,[r12,#0x6c]` = array base 0x60 + record +0x0c).
pub const COL_CACHE_I_REG_OFFSET: usize = 0x0c;

/// used_as_column_cache — original: `FUN_083966a0` @ 0x083966a0 (64
/// bytes; 3 `bl` call sites).
///
/// `usedAsColumnCache`: return 1 when any column-cache record's `iReg`
/// lies inside the inclusive register range `[start, end]`, else 0.
/// Signed comparisons throughout, exactly as the original's
/// `blt`/`movle`/`bgt`; `nColCache` is read once at entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn used_as_column_cache(parse: *mut u8, start: i32, end: i32) -> i32 {
    let n_col_cache = (parse.add(N_COL_CACHE_OFFSET) as *const i32).read();
    let mut i: i32 = 0;
    while n_col_cache > i {
        let record = parse.add(A_COL_CACHE_OFFSET + i as usize * COL_CACHE_RECORD_SIZE);
        let i_reg = (record.add(COL_CACHE_I_REG_OFFSET) as *const i32).read();
        if i_reg >= start && i_reg <= end {
            return 1;
        }
        i += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A `Parse` context: word-aligned so the count and `iReg` reads
    /// are aligned, as they are on target. 0xe0 bytes covers the count
    /// at +0x58 plus eight 16-byte `aColCache` records at +0x60.
    #[repr(align(4))]
    struct ParseContext([u8; 0xe0]);

    impl ParseContext {
        /// A context whose cache holds `i_regs` (one `iReg` per record,
        /// records laid out at the 16-byte stride). Other record fields
        /// keep the 0xa5 fill — the scan must not read them.
        fn new(i_regs: &[i32]) -> Self {
            let mut ctx = ParseContext([0xa5; 0xe0]);
            ctx.0[N_COL_CACHE_OFFSET..N_COL_CACHE_OFFSET + 4]
                .copy_from_slice(&(i_regs.len() as i32).to_le_bytes());
            for (slot, i_reg) in i_regs.iter().enumerate() {
                let at = A_COL_CACHE_OFFSET + slot * COL_CACHE_RECORD_SIZE + COL_CACHE_I_REG_OFFSET;
                ctx.0[at..at + 4].copy_from_slice(&i_reg.to_le_bytes());
            }
            ctx
        }
        fn with_count(count: i32) -> Self {
            let mut ctx = ParseContext([0xa5; 0xe0]);
            ctx.0[N_COL_CACHE_OFFSET..N_COL_CACHE_OFFSET + 4]
                .copy_from_slice(&count.to_le_bytes());
            ctx
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    fn scan(ctx: &mut ParseContext, start: i32, end: i32) -> i32 {
        unsafe { used_as_column_cache(ctx.ptr(), start, end) }
    }

    #[test]
    fn empty_cache_reports_not_cached() {
        let mut ctx = ParseContext::new(&[]);
        assert_eq!(scan(&mut ctx, 1, 1), 0);
        assert_eq!(scan(&mut ctx, i32::MIN, i32::MAX), 0, "even the widest range hits nothing");
    }

    #[test]
    fn negative_count_scans_nothing() {
        // The original's loop head is a signed `bgt` on nColCache: a
        // negative count behaves exactly like an empty cache, even when
        // a record would match.
        let mut ctx = ParseContext::with_count(-3);
        assert_eq!(scan(&mut ctx, 1, 100), 0);
    }

    #[test]
    fn the_range_bounds_are_inclusive() {
        let mut ctx = ParseContext::new(&[5, 9]);
        assert_eq!(scan(&mut ctx, 5, 8), 1, "iReg == start is a hit");
        assert_eq!(scan(&mut ctx, 6, 9), 1, "iReg == end is a hit");
        assert_eq!(scan(&mut ctx, 5, 9), 1, "both bounds bracket a record each");
    }

    #[test]
    fn registers_outside_the_range_do_not_hit() {
        let mut ctx = ParseContext::new(&[4, 10]);
        assert_eq!(scan(&mut ctx, 5, 9), 0, "start-1 and end+1 are both outside");
        assert_eq!(scan(&mut ctx, 11, 20), 0, "whole cache below the range");
        assert_eq!(scan(&mut ctx, 0, 3), 0, "whole cache above the range");
    }

    #[test]
    fn every_record_up_to_the_count_is_scanned() {
        let i_regs: Vec<i32> = (20..28).collect();
        let mut ctx = ParseContext::new(&i_regs);
        assert_eq!(
            scan(&mut ctx, 27, 27),
            1,
            "a hit in the eighth (last) record is found — full stride walk"
        );
        assert_eq!(scan(&mut ctx, 28, 30), 0);
    }

    #[test]
    fn records_past_the_count_are_ignored() {
        // Count says one record; a matching `iReg` sits in record 1.
        let mut ctx = ParseContext::new(&[30]);
        let past_count = A_COL_CACHE_OFFSET + COL_CACHE_RECORD_SIZE + COL_CACHE_I_REG_OFFSET;
        ctx.0[past_count..past_count + 4].copy_from_slice(&7i32.to_le_bytes());
        assert_eq!(scan(&mut ctx, 7, 7), 0, "record 1 is beyond nColCache == 1");
        assert_eq!(scan(&mut ctx, 30, 30), 1);
    }

    #[test]
    fn register_zero_inside_the_range_is_a_hit() {
        // 3.5.9 has no `iReg != 0` guard (later versions do); the
        // firmware matches 3.5.9 — no zero test in the disassembly.
        let mut ctx = ParseContext::new(&[0]);
        assert_eq!(scan(&mut ctx, 0, 0), 1);
        assert_eq!(scan(&mut ctx, 0, 5), 1);
        assert_eq!(scan(&mut ctx, 1, 5), 0, "0 is below the range, not skipped as unset");
    }

    #[test]
    fn comparisons_are_signed() {
        let mut ctx = ParseContext::new(&[-3, 7]);
        assert_eq!(scan(&mut ctx, -5, -1), 1, "negative iReg inside a negative range");
        assert_eq!(scan(&mut ctx, 0, 10), 1, "the negative record stays below the range");
        assert_eq!(scan(&mut ctx, -2, 6), 0, "a range between the two records hits neither");
    }

    #[test]
    fn inverted_range_can_still_hit() {
        // Callers pass start <= end, but the original just compares:
        // start > end can match only a record that is simultaneously
        // >= start and <= end — impossible, so the answer is 0. Pins
        // that the port did not "fix" the argument order.
        let mut ctx = ParseContext::new(&[5]);
        assert_eq!(scan(&mut ctx, 9, 4), 0);
    }

    #[test]
    fn cache_content_is_never_written() {
        let i_regs = [4i32, 5, 6];
        let mut ctx = ParseContext::new(&i_regs);
        let before = ctx.0;
        assert_eq!(scan(&mut ctx, 5, 5), 1);
        assert_eq!(ctx.0, before, "the scan is read-only");
    }
}
