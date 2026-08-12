//! The code generator's consecutive-register draw from the
//! temp-register range pool.
//!
//! - `get_temp_range` — original: `FUN_0837a354` @ 0x0837a354 (104
//!   bytes; 11 `bl` call sites, binary-scanned; no tail `b` sites).
//!   SQLite 3.5.9's `sqlite3GetTempRange` (expr.c), the allocator
//!   expression-codegen paths use to reserve a block of consecutive
//!   VDBE registers (function-argument lists, ORDER BY sorter rows,
//!   IN-operator ephemeral tables). The companion
//!   `sqlite3ReleaseTempRange` (unported) returns spent ranges to the
//!   pool; [`crate::sqlite::get_temp_reg`] is the single-register
//!   sibling.
//!
//! Upstream 3.5.9 (expr.c, verbatim):
//!
//! ```c
//! int sqlite3GetTempRange(Parse *pParse, int nReg){
//!   int i, n;
//!   i = pParse->iRangeReg;
//!   n = pParse->nRangeReg;
//!   if( nReg<=n && !usedAsColumnCache(pParse, i, i+n-1) ){
//!     pParse->iRangeReg += nReg;
//!     pParse->nRangeReg -= nReg;
//!   }else{
//!     i = pParse->nMem+1;
//!     pParse->nMem += nReg;
//!   }
//!   return i;
//! }
//! ```
//!
//! Unlike the sibling `get_temp_reg` @ 0x0837a3bc, the 3.5.9
//! discarded-verdict bug does NOT apply here: upstream uses the
//! `usedAsColumnCache` answer to gate the pool path, and the firmware
//! does too — the `bl 0x083966a0` at 0x0837a380 is followed by
//! `cmp r0,#0x0` and a full set of `eq`-conditioned pool updates.
//! The firmware matches upstream 3.5.9 instruction-for-intent,
//! including its two quirks:
//!
//! - The cache probe covers the WHOLE remaining pool range
//!   `[iRangeReg, iRangeReg + nRangeReg - 1]` (`add r0,r6,r0;
//!   sub r2,r0,#0x1` from the `nRangeReg` load), not just the
//!   `nReg` registers about to be drawn. A cached register anywhere
//!   in the pool's remaining range — even outside the requested
//!   sub-range — forces the `nMem` carve.
//! - The `nMem` path returns `nMem + 1` but advances `nMem` by only
//!   `nReg` (`ldr r0,[r4,#0x48]; add r6,r0,#0x1; add r0,r0,r5;
//!   str r0,[r4,#0x48]`), i.e. the returned block is
//!   `[old_nMem + 1, old_nMem + nReg]`, exactly upstream's
//!   `i = pParse->nMem+1; pParse->nMem += nReg;`.
//!
//! Firmware algorithm (verified against osos.asm
//! 0x0837a354..0x0837a3b8):
//!
//! ```text
//! i = iRangeReg; n = nRangeReg          // both loaded ONCE at entry
//! if n_reg <= n (signed; bgt skips the scan):
//!     if usedAsColumnCache(parse, i, i+n-1) == 0:   // @ 0x083966a0
//!         iRangeReg += n_reg; nRangeReg -= n_reg
//!         return i
//! nMem += n_reg
//! return <old nMem> + 1
//! ```
//!
//! `Parse` fields used (fixed-width, host-independent):
//!
//! ```text
//! +0x38 nRangeReg  (i32)  pool slots remaining — reloaded at entry only
//! +0x3c iRangeReg  (i32)  first pooled register
//! +0x48 nMem       (i32)  high-water mark of VDBE registers used
//! ```
//!
//! Deviations: none. The callee [`crate::sqlite::used_as_column_cache`]
//! @ 0x083966a0 is ported and called directly — no seam: its verdict is load-bearing
//! here, and the real scan is the only behaviorally correct model.

/// Byte offset of `Parse.nRangeReg` (original: `ldr r0,[r0,#0x38]` at
/// entry; reloaded as `ldreq r0,[r4,#0x38]` for the pool-path store).
pub const N_RANGE_REG_OFFSET: usize = 0x38;

/// Byte offset of `Parse.iRangeReg` (original: `ldr r6,[r0,#0x3c]` at
/// entry; `r6` carries it to the pool updates and the return).
pub const I_RANGE_REG_OFFSET: usize = 0x3c;

/// Byte offset of `Parse.nMem` (original: `ldr r0,[r4,#0x48]` /
/// `add r0,r0,r5` / `str r0,[r4,#0x48]` on the carve path). Same field
/// [`crate::sqlite::get_temp_reg::N_MEM_OFFSET`] names.
pub const N_MEM_OFFSET: usize = 0x48;

/// get_temp_range — original: `FUN_0837a354` @ 0x0837a354 (104 bytes;
/// 11 `bl` call sites).
///
/// `sqlite3GetTempRange`: reserve `n_reg` consecutive VDBE registers
/// and return the first. Draws from the range pool when it holds at
/// least `n_reg` slots (signed comparison, as the original's
/// `cmp r1,r0; bgt`) AND the ported column-cache scan
/// [`crate::sqlite::used_as_column_cache::used_as_column_cache`] finds no cached register in the whole
/// remaining pool range `[iRangeReg, iRangeReg + nRangeReg - 1]`;
/// otherwise carves the block off `nMem`, returning the old `nMem + 1`
/// and advancing `nMem` by `n_reg` only. All arithmetic wraps like the
/// original's ARM `add`/`sub`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn get_temp_range(parse: *mut u8, n_reg: i32) -> i32 {
    let i = (parse.add(I_RANGE_REG_OFFSET) as *const i32).read();
    let n = (parse.add(N_RANGE_REG_OFFSET) as *const i32).read();
    if n_reg <= n
        && super::used_as_column_cache::used_as_column_cache(
            parse,
            i,
            i.wrapping_add(n).wrapping_sub(1),
        ) == 0
    {
        (parse.add(I_RANGE_REG_OFFSET) as *mut i32).write(i.wrapping_add(n_reg));
        (parse.add(N_RANGE_REG_OFFSET) as *mut i32).write(n.wrapping_sub(n_reg));
        i
    } else {
        let n_mem = parse.add(N_MEM_OFFSET) as *mut i32;
        let old = n_mem.read();
        n_mem.write(old.wrapping_add(n_reg));
        old.wrapping_add(1)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::used_as_column_cache::{
        A_COL_CACHE_OFFSET, COL_CACHE_I_REG_OFFSET, COL_CACHE_RECORD_SIZE, N_COL_CACHE_OFFSET,
    };

    /// A `Parse` context: word-aligned so the pool-field and `nMem`
    /// accesses are aligned, as they are on target. 0xe0 bytes covers
    /// the highest field the scan can touch (eight 16-byte `aColCache`
    /// records at +0x60) with headroom.
    #[repr(align(4))]
    struct ParseContext([u8; 0xe0]);

    impl ParseContext {
        /// A context with pool state `(i_range_reg, n_range_reg)`,
        /// high-water mark `n_mem`, and a column cache holding
        /// `i_regs` (one `iReg` per record at the 16-byte stride).
        /// Everything else keeps the 0xa5 fill — the function and its
        /// callee must not read other fields.
        fn new(i_range_reg: i32, n_range_reg: i32, n_mem: i32, i_regs: &[i32]) -> Self {
            let mut ctx = ParseContext([0xa5; 0xe0]);
            ctx.0[N_RANGE_REG_OFFSET..N_RANGE_REG_OFFSET + 4]
                .copy_from_slice(&n_range_reg.to_le_bytes());
            ctx.0[I_RANGE_REG_OFFSET..I_RANGE_REG_OFFSET + 4]
                .copy_from_slice(&i_range_reg.to_le_bytes());
            ctx.0[N_MEM_OFFSET..N_MEM_OFFSET + 4].copy_from_slice(&n_mem.to_le_bytes());
            ctx.0[N_COL_CACHE_OFFSET..N_COL_CACHE_OFFSET + 4]
                .copy_from_slice(&(i_regs.len() as i32).to_le_bytes());
            for (slot, i_reg) in i_regs.iter().enumerate() {
                let at = A_COL_CACHE_OFFSET + slot * COL_CACHE_RECORD_SIZE + COL_CACHE_I_REG_OFFSET;
                ctx.0[at..at + 4].copy_from_slice(&i_reg.to_le_bytes());
            }
            ctx
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn get(&self, offset: usize) -> i32 {
            i32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
        }
        fn i_range_reg(&self) -> i32 {
            self.get(I_RANGE_REG_OFFSET)
        }
        fn n_range_reg(&self) -> i32 {
            self.get(N_RANGE_REG_OFFSET)
        }
        fn n_mem(&self) -> i32 {
            self.get(N_MEM_OFFSET)
        }
    }

    fn draw(ctx: &mut ParseContext, n_reg: i32) -> i32 {
        unsafe { get_temp_range(ctx.ptr(), n_reg) }
    }

    #[test]
    fn empty_pool_carves_off_n_mem() {
        // nRangeReg == 0 < n_reg: the original's `bgt` skips the scan
        // entirely and takes the carve path.
        let mut ctx = ParseContext::new(0, 0, 7, &[]);
        let first = draw(&mut ctx, 3);
        assert_eq!(first, 8, "returns old nMem + 1 (original: `add r6,r0,#0x1`)");
        assert_eq!(ctx.n_mem(), 10, "nMem advances by n_reg ONLY — not n_reg + 1");
        assert_eq!(ctx.i_range_reg(), 0, "the pool fields are untouched");
        assert_eq!(ctx.n_range_reg(), 0);
    }

    #[test]
    fn oversized_request_carves_even_with_pool_and_clear_cache() {
        // Pool holds 3 slots, request is 4, cache is empty: the
        // `n_reg <= n` gate fails, so the pool is not touched even
        // though the scan would have cleared it.
        let mut ctx = ParseContext::new(10, 3, 20, &[]);
        let first = draw(&mut ctx, 4);
        assert_eq!(first, 21);
        assert_eq!(ctx.n_mem(), 24);
        assert_eq!(ctx.i_range_reg(), 10);
        assert_eq!(ctx.n_range_reg(), 3, "a failed gate leaves the whole pool intact");
    }

    #[test]
    fn pool_path_returns_first_slot_and_shrinks_pool() {
        let mut ctx = ParseContext::new(10, 8, 20, &[]);
        let first = draw(&mut ctx, 3);
        assert_eq!(first, 10, "the draw is the pooled [iRangeReg, iRangeReg + n_reg)");
        assert_eq!(ctx.i_range_reg(), 13);
        assert_eq!(ctx.n_range_reg(), 5);
        assert_eq!(ctx.n_mem(), 20, "the pool path never touches nMem");
    }

    #[test]
    fn full_pool_draw_empties_the_pool() {
        let mut ctx = ParseContext::new(5, 4, 1, &[]);
        let first = draw(&mut ctx, 4);
        assert_eq!(first, 5);
        assert_eq!(ctx.i_range_reg(), 9);
        assert_eq!(ctx.n_range_reg(), 0);
        assert_eq!(ctx.n_mem(), 1);
        // ...and the next draw of any size falls through to nMem.
        let second = draw(&mut ctx, 1);
        assert_eq!(second, 2);
        assert_eq!(ctx.n_mem(), 2);
    }

    #[test]
    fn cached_register_inside_request_forces_carve() {
        // The drawn sub-range [10, 11] overlaps the cached register 11.
        let mut ctx = ParseContext::new(10, 8, 20, &[11]);
        let first = draw(&mut ctx, 2);
        assert_eq!(first, 21, "a cache hit anywhere in the probe range vetoes the pool");
        assert_eq!(ctx.n_mem(), 22);
        assert_eq!(ctx.i_range_reg(), 10);
        assert_eq!(ctx.n_range_reg(), 8);
    }

    #[test]
    fn probe_covers_whole_pool_range_not_just_the_request() {
        // Request [10, 11] is cache-clear, but register 17 — inside the
        // pool's remaining range [10, 17], OUTSIDE the request — is
        // cached. Upstream 3.5.9 probes (i, i+n-1), so this is a hit;
        // a "fixed" probe of (i, i+n_reg-1) would take the pool path.
        let mut ctx = ParseContext::new(10, 8, 20, &[17]);
        let first = draw(&mut ctx, 2);
        assert_eq!(first, 21, "the probe end is iRangeReg + nRangeReg - 1 (upstream quirk)");
        assert_eq!(ctx.n_mem(), 22);
        assert_eq!(ctx.i_range_reg(), 10);
        assert_eq!(ctx.n_range_reg(), 8);
    }

    #[test]
    fn successive_draws_consume_pool_then_carve() {
        let mut ctx = ParseContext::new(10, 6, 20, &[]);
        assert_eq!(draw(&mut ctx, 2), 10);
        assert_eq!(draw(&mut ctx, 4), 12, "the pool hands out its last slot");
        assert_eq!(ctx.n_range_reg(), 0);
        assert_eq!(draw(&mut ctx, 2), 21, "pool exhausted: carve at old nMem + 1");
        assert_eq!(ctx.n_mem(), 22);
        assert_eq!(ctx.i_range_reg(), 16, "a carve never rewinds the pool");
    }

    #[test]
    fn negative_pool_size_behaves_like_empty() {
        // The gate is a signed `bgt`: a negative nRangeReg fails it for
        // any non-negative request.
        let mut ctx = ParseContext::new(10, -2, 30, &[]);
        let first = draw(&mut ctx, 1);
        assert_eq!(first, 31);
        assert_eq!(ctx.n_mem(), 31);
        assert_eq!(ctx.n_range_reg(), -2);
    }

    #[test]
    fn n_mem_arithmetic_wraps_like_arm_add() {
        let mut ctx = ParseContext::new(0, 0, i32::MAX - 1, &[]);
        let first = draw(&mut ctx, 3);
        assert_eq!(first, i32::MAX, "old nMem + 1 wraps without trapping");
        assert_eq!(ctx.n_mem(), i32::MIN + 1, "nMem += n_reg wraps (`add r0,r0,r5`)");
    }
}
