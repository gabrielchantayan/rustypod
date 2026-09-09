//! Mark column-cache registers whose affinities must be reapplied.
//!
//! `expr_cache_affinity_change` — original: `FUN_08376b48` @ `0x08376b48`
//! (64 bytes; 15 unconditional `bl` call sites, binary-scanned; no predicated
//! `bl` or tail `b` call sites).
//!
//! SQLite 3.5.9's `sqlite3ExprCacheAffinityChange` (`expr.c`). The function
//! loads `Parse.nColCache` once, computes the inclusive register interval
//! `[first_reg, first_reg + count - 1]` with ARM's wrapping arithmetic, then
//! walks each 16-byte `ColCache` record. It sets only `affChange` to one for
//! records whose signed `iReg` lies in that interval. The routine has no NULL
//! guard; all 15 callers invoke it unconditionally after obtaining a valid
//! parse context.
//!
//! Deliberate deviations: none. In particular, zero or overflowing `count`
//! retains the firmware's wrapping endpoint rather than being rejected.

use super::used_as_column_cache::{
    A_COL_CACHE_OFFSET, COL_CACHE_I_REG_OFFSET, COL_CACHE_RECORD_SIZE, N_COL_CACHE_OFFSET,
};

/// Record-relative offset of `ColCache.affChange` (the `strble` at
/// `0x08376b74` writes exactly this byte).
pub const COL_CACHE_AFF_CHANGE_OFFSET: usize = 0x08;

/// expr_cache_affinity_change — original: `FUN_08376b48` @ `0x08376b48`
/// (64 bytes; 15 unconditional `bl` call sites; no predicated calls).
///
/// `sqlite3ExprCacheAffinityChange`: mark cached columns that use a VDBE
/// register in `[first_reg, first_reg + count - 1]` so their affinity is
/// re-applied when next consumed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_cache_affinity_change(
    parse: *mut u8,
    first_reg: i32,
    count: i32,
) {
    let last_reg = first_reg.wrapping_add(count).wrapping_sub(1);
    let n_col_cache = (parse.add(N_COL_CACHE_OFFSET) as *const i32).read();
    let mut i = 0i32;

    while n_col_cache > i {
        let record = parse.add(A_COL_CACHE_OFFSET + i as usize * COL_CACHE_RECORD_SIZE);
        let i_reg = (record.add(COL_CACHE_I_REG_OFFSET) as *const i32).read();
        if i_reg >= first_reg && i_reg <= last_reg {
            record.add(COL_CACHE_AFF_CHANGE_OFFSET).write(1);
        }
        i = i.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[repr(align(4))]
    struct ParseContext([u8; 0xe0]);

    impl ParseContext {
        fn new(records: &[(i32, u8)]) -> Self {
            let mut ctx = ParseContext([0xa5; 0xe0]);
            ctx.0[N_COL_CACHE_OFFSET..N_COL_CACHE_OFFSET + 4]
                .copy_from_slice(&(records.len() as i32).to_le_bytes());
            for (i, &(i_reg, aff_change)) in records.iter().enumerate() {
                let record = A_COL_CACHE_OFFSET + i * COL_CACHE_RECORD_SIZE;
                ctx.0[record + COL_CACHE_I_REG_OFFSET..record + COL_CACHE_I_REG_OFFSET + 4]
                    .copy_from_slice(&i_reg.to_le_bytes());
                ctx.0[record + COL_CACHE_AFF_CHANGE_OFFSET] = aff_change;
            }
            ctx
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        fn aff_change(&self, i: usize) -> u8 {
            self.0[A_COL_CACHE_OFFSET + i * COL_CACHE_RECORD_SIZE + COL_CACHE_AFF_CHANGE_OFFSET]
        }
    }

    fn mark(ctx: &mut ParseContext, first_reg: i32, count: i32) {
        unsafe { expr_cache_affinity_change(ctx.ptr(), first_reg, count) }
    }

    #[test]
    fn marks_each_inclusive_range_endpoint_only() {
        let mut ctx = ParseContext::new(&[(4, 0), (5, 0), (6, 0), (7, 0), (8, 0)]);
        mark(&mut ctx, 5, 3);
        assert_eq!(
            [ctx.aff_change(0), ctx.aff_change(1), ctx.aff_change(2), ctx.aff_change(3), ctx.aff_change(4)],
            [0, 1, 1, 1, 0],
        );
    }

    #[test]
    fn preserves_existing_marks_and_all_other_record_bytes() {
        let mut ctx = ParseContext::new(&[(10, 0), (20, 0xa5)]);
        let before = ctx.0;
        mark(&mut ctx, 10, 1);
        assert_eq!(ctx.aff_change(0), 1);
        assert_eq!(ctx.aff_change(1), 0xa5, "an already marked out-of-range record stays intact");
        for (offset, (&after, &original)) in ctx.0.iter().zip(before.iter()).enumerate() {
            if offset == A_COL_CACHE_OFFSET + COL_CACHE_AFF_CHANGE_OFFSET {
                continue;
            }
            assert_eq!(after, original, "only the matching affChange byte is written");
        }
    }

    #[test]
    fn negative_cache_count_scans_nothing() {
        let mut ctx = ParseContext::new(&[(7, 0)]);
        ctx.0[N_COL_CACHE_OFFSET..N_COL_CACHE_OFFSET + 4].copy_from_slice(&(-1i32).to_le_bytes());
        mark(&mut ctx, 7, 1);
        assert_eq!(ctx.aff_change(0), 0);
    }

    #[test]
    fn zero_count_at_minimum_register_wraps_to_full_signed_range() {
        let mut ctx = ParseContext::new(&[(i32::MIN, 0), (0, 0), (i32::MAX, 0)]);
        mark(&mut ctx, i32::MIN, 0);
        assert_eq!(
            [ctx.aff_change(0), ctx.aff_change(1), ctx.aff_change(2)],
            [1, 1, 1],
            "ARM add/sub wraps: MIN + 0 - 1 is MAX",
        );
    }

    #[test]
    fn overflowing_endpoint_does_not_create_an_unsigned_range() {
        let mut ctx = ParseContext::new(&[(i32::MAX, 0), (i32::MIN, 0)]);
        mark(&mut ctx, i32::MAX, 2);
        assert_eq!(
            [ctx.aff_change(0), ctx.aff_change(1)],
            [0, 0],
            "the wrapped endpoint makes the signed interval empty",
        );
    }
}
