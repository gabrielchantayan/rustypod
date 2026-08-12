//! The code generator's single-register draw from the temp-register
//! pool.
//!
//! - `get_temp_reg` — original: `FUN_0837a3bc` @ 0x0837a3bc (80 bytes;
//!   35 `bl` call sites, binary-scanned; no tail `b` sites). SQLite
//!   3.5.9's `sqlite3GetTempReg` (expr.c), the allocator every
//!   expression-codegen path uses to reserve one VDBE register for an
//!   intermediate value. The companion `release_temp_reg` @ 0x08381f98
//!   ([`crate::sqlite::parse`]) returns spent registers to the pool.
//!
//! Upstream 3.5.9 intent: reuse a pooled register from `aTempReg`
//! unless the column cache still references it, otherwise grow the
//! frame by one (`++pParse->nMem`). The upstream body carries a famous
//! bug — the scan loop's `continue` and its fall-through merge at the
//! same `i++`, so the post-loop `if( i>=pParse->nTempReg )` is ALWAYS
//! true and the pop-from-pool tail (including an increment-less `while`
//! that would spin forever) is unreachable. ADS 1.0.1 proved exactly
//! that: the shipped function keeps the scan calls (it cannot see into
//! the separately-compiled `usedAsColumnCache`, so it may not delete
//! them), folds the dead `if( usedAsColumnCache(...) ) continue;`
//! branch away, deletes the whole pop tail, and UNCONDITIONALLY returns
//! `++pParse->nMem`. Net firmware behavior: the temp-register pool is
//! write-only — `release_temp_reg` pushes, nothing ever pops — and
//! every draw carves a fresh register off `nMem`.
//!
//! Firmware algorithm (verified against osos.asm
//! 0x0837a3bc..0x0837a40c):
//!
//! ```text
//! if nTempReg != 0:
//!     for i in 0..nTempReg:                  // count re-read each pass
//!         r = aTempReg[i]
//!         usedAsColumnCache(parse, r, r)     // @ 0x083966a0; result DISCARDED
//! return ++nMem
//! ```
//!
//! `Parse` fields used (all fixed-width, so plain byte offsets are
//! host-independent — no pointer fields are touched):
//!
//! ```text
//! +0x15 nTempReg   (u8)      pool slots in use — re-read each iteration
//! +0x18 aTempReg   (i32[8])  the pool (the same fields `release_temp_reg` writes)
//! +0x48 nMem       (i32)     high-water mark of VDBE registers used
//! ```
//!
//! Deviations:
//! - `usedAsColumnCache` @ 0x083966a0 is UNPORTED and rides the
//!   [`TEMP_REG_OPS`] seam; the shipped default
//!   [`missing_used_as_column_cache`] reports "not cached" (0). The
//!   answer cannot change `get_temp_reg`'s observable behavior in any
//!   way — the original discards it — so the slot exists purely so
//!   host tests can observe the scan's arguments and iteration count,
//!   and so the 0x083966a0 port can drop in later.

/// Byte offset of `Parse.nTempReg` (original: `ldrb r0,[r0,#0x15]` at
/// entry and `ldrb r0,[r4,#0x15]` in the loop head).
pub const N_TEMP_REG_OFFSET: usize = 0x15;
/// Byte offset of `Parse.aTempReg` (original: `ldr r1,[r0,#0x18]` with
/// `r0 = parse + i*4`).
pub const A_TEMP_REG_OFFSET: usize = 0x18;
/// Byte offset of `Parse.nMem` (original: `ldr r0,[r4,#0x48]` /
/// `add r0,r0,#0x1` / `str r0,[r4,#0x48]`).
pub const N_MEM_OFFSET: usize = 0x48;

/// Indirect dispatch for the unported column-cache scan @ 0x083966a0
/// (`usedAsColumnCache`), kept behind the table so host tests can
/// observe the scan's arguments (the house pattern —
/// `sqlite/cell_size.rs`).
#[derive(Clone, Copy)]
pub struct TempRegOps {
    /// `usedAsColumnCache` @ 0x083966a0 (UNPORTED —
    /// [`missing_used_as_column_cache`] is the shipped default):
    /// return 1 when any column-cache entry (`Parse.aColCache` at
    /// +0x60, 16-byte records with `iReg` at record +0x0c, `nColCache`
    /// entries at +0x58) holds a register in `[start, end]`, else 0.
    /// `get_temp_reg` passes `(r, r)` and DISCARDS the result, exactly
    /// as the original does.
    pub used_as_column_cache: unsafe extern "C" fn(parse: *mut u8, start: i32, end: i32) -> i32,
}

/// Stand-in for the unported `usedAsColumnCache` @ 0x083966a0: report
/// "no column-cache entry uses the register" (0). With the column
/// cache unmodeled there is nothing to report, and the answer is
/// behaviorally free anyway — the one caller discards it.
unsafe extern "C" fn missing_used_as_column_cache(_parse: *mut u8, _start: i32, _end: i32) -> i32 {
    0
}

/// Wired default for [`TEMP_REG_OPS`]: the "not cached" stand-in while
/// 0x083966a0 is unported.
pub const DEFAULT_TEMP_REG_OPS: TempRegOps = TempRegOps {
    used_as_column_cache: missing_used_as_column_cache,
};

/// Active model of the `usedAsColumnCache` scan in [`get_temp_reg`].
/// Host tests replace the slot to observe the exact arguments.
pub static mut TEMP_REG_OPS: TempRegOps = DEFAULT_TEMP_REG_OPS;

/// Reads the scan slot. Volatile so LLVM cannot constant-fold the load
/// to the stand-in default (the house pattern — `sqlite/cell_size.rs`).
#[inline(always)]
pub(crate) unsafe fn used_as_column_cache_op() -> unsafe extern "C" fn(*mut u8, i32, i32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(TEMP_REG_OPS.used_as_column_cache))
}

/// get_temp_reg — original: `FUN_0837a3bc` @ 0x0837a3bc (80 bytes;
/// 35 `bl` call sites).
///
/// `sqlite3GetTempReg`: draw one VDBE register for an intermediate
/// value. Scans the pool's `nTempReg` entries through the
/// [`TEMP_REG_OPS`] column-cache check (the count byte is re-read on
/// every pass, as the original's in-loop `ldrb` does), discards every
/// answer, then returns `++parse.nMem` — the original's `add r0,r0,#0x1;
/// str r0,[r4,#0x48]`, with wrapping increment semantics (ARM `add`).
/// The pool is never popped: that is the upstream 3.5.9 bug made
/// permanent by dead-code elimination, not a porting shortcut (see the
/// module header).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn get_temp_reg(parse: *mut u8) -> i32 {
    let mut i: i32 = 0;
    while i < parse.add(N_TEMP_REG_OFFSET).read() as i32 {
        let reg = (parse.add(A_TEMP_REG_OFFSET) as *const i32)
            .add(i as usize)
            .read();
        (used_as_column_cache_op())(parse, reg, reg);
        i += 1;
    }
    let n_mem = parse.add(N_MEM_OFFSET) as *mut i32;
    let next = n_mem.read().wrapping_add(1);
    n_mem.write(next);
    next
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the scan slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every `(start, end)` pair the scan slot was called with, in
    /// order. (The `parse` pointer is the context's own address in
    /// every test, so recording it adds nothing.)
    static mut CALLS: Vec<(i32, i32)> = Vec::new();

    /// What the mock reports from its next call.
    static mut MOCK_REPLY: i32 = 0;

    /// When true, the mock shrinks `nTempReg` to 1 during its first
    /// call — the probe for the original's re-read-the-count loop head.
    static mut MOCK_SHRINKS_POOL: bool = false;

    unsafe extern "C" fn recording_used_as_column_cache(
        parse: *mut u8,
        start: i32,
        end: i32,
    ) -> i32 {
        (*core::ptr::addr_of_mut!(CALLS)).push((start, end));
        if *core::ptr::addr_of!(MOCK_SHRINKS_POOL) {
            parse.add(N_TEMP_REG_OFFSET).write(1);
        }
        *core::ptr::addr_of!(MOCK_REPLY)
    }

    /// Installs the recording mock and returns the lock guard, which
    /// must stay alive for the whole test.
    fn bench() -> MutexGuard<'static, ()> {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            *core::ptr::addr_of_mut!(MOCK_REPLY) = 0;
            *core::ptr::addr_of_mut!(MOCK_SHRINKS_POOL) = false;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(TEMP_REG_OPS),
                TempRegOps {
                    used_as_column_cache: recording_used_as_column_cache,
                },
            );
        }
        ops_guard
    }

    fn calls() -> Vec<(i32, i32)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// A `Parse` context: word-aligned so the pool reads and the `nMem`
    /// store are aligned, as they are on target. 0x60 bytes covers the
    /// highest field touched (`nMem` at +0x48) with headroom.
    #[repr(align(4))]
    struct ParseContext([u8; 0x60]);

    impl ParseContext {
        fn new(count: u8, pool: &[i32], n_mem: i32) -> Self {
            let mut ctx = ParseContext([0xa5; 0x60]);
            ctx.0[N_TEMP_REG_OFFSET] = count;
            for (slot, reg) in pool.iter().enumerate() {
                let at = A_TEMP_REG_OFFSET + slot * 4;
                ctx.0[at..at + 4].copy_from_slice(&reg.to_le_bytes());
            }
            ctx.0[N_MEM_OFFSET..N_MEM_OFFSET + 4].copy_from_slice(&n_mem.to_le_bytes());
            ctx
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn count(&self) -> u8 {
            self.0[N_TEMP_REG_OFFSET]
        }
        fn slot(&self, index: usize) -> i32 {
            let at = A_TEMP_REG_OFFSET + index * 4;
            i32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
        }
        fn n_mem(&self) -> i32 {
            i32::from_le_bytes(self.0[N_MEM_OFFSET..N_MEM_OFFSET + 4].try_into().unwrap())
        }
    }

    #[test]
    fn empty_pool_bumps_n_mem_without_scanning() {
        let _guard = bench();
        let mut ctx = ParseContext::new(0, &[], 41);
        let reg = unsafe { get_temp_reg(ctx.ptr()) };
        assert_eq!(reg, 42, "returns the INCREMENTED nMem (original: r0 = nMem + 1)");
        assert_eq!(ctx.n_mem(), 42, "nMem is stored back bumped by one");
        assert_eq!(ctx.count(), 0);
        assert_eq!(calls(), Vec::new(), "an empty pool is never scanned");
    }

    #[test]
    fn full_pool_is_scanned_in_order_but_never_popped() {
        let _guard = bench();
        let pool: Vec<i32> = (10..18).collect();
        let mut ctx = ParseContext::new(8, &pool, 3);
        let reg = unsafe { get_temp_reg(ctx.ptr()) };
        assert_eq!(reg, 4, "even with a full pool the draw is ++nMem — the 3.5.9 dead-pop bug");
        assert_eq!(ctx.n_mem(), 4);
        assert_eq!(
            calls(),
            pool.iter().map(|&r| (r, r)).collect::<Vec<_>>(),
            "each pooled register is probed as (r, r), in pool order"
        );
        assert_eq!(ctx.count(), 8, "the pool count is untouched — nothing is ever popped");
        for (slot, &r) in pool.iter().enumerate() {
            assert_eq!(ctx.slot(slot), r, "pool slot {slot} survives the scan");
        }
    }

    #[test]
    fn scan_verdict_is_discarded() {
        let _guard = bench();
        let pool = [5i32, 6, 7];
        let mut outcomes = Vec::new();
        for reply in [0i32, 1] {
            unsafe {
                (*core::ptr::addr_of_mut!(CALLS)).clear();
                *core::ptr::addr_of_mut!(MOCK_REPLY) = reply;
            }
            let mut ctx = ParseContext::new(3, &pool, 100);
            let reg = unsafe { get_temp_reg(ctx.ptr()) };
            outcomes.push((reg, ctx.n_mem(), ctx.count(), calls()));
        }
        assert_eq!(
            outcomes[0], outcomes[1],
            "'cached' and 'not cached' verdicts produce byte-identical outcomes"
        );
        assert_eq!(outcomes[0].0, 101);
    }

    #[test]
    fn pool_count_is_reread_on_every_pass() {
        let _guard = bench();
        unsafe { *core::ptr::addr_of_mut!(MOCK_SHRINKS_POOL) = true };
        let pool = [5i32, 6, 7];
        let mut ctx = ParseContext::new(3, &pool, 0);
        let reg = unsafe { get_temp_reg(ctx.ptr()) };
        assert_eq!(reg, 1);
        assert_eq!(
            calls(),
            std::vec![(5, 5)],
            "the scan stops when the callee shrinks nTempReg mid-loop — \
             the original re-reads the byte in the loop head (`ldrb` at 0x0837a3f0)"
        );
        assert_eq!(ctx.count(), 1, "the callee's shrink is what the loop saw");
    }

    #[test]
    fn n_mem_increment_wraps_like_arm_add() {
        let _guard = bench();
        let mut ctx = ParseContext::new(0, &[], i32::MAX);
        let reg = unsafe { get_temp_reg(ctx.ptr()) };
        assert_eq!(reg, i32::MIN, "`add r0,r0,#0x1` wraps; no trapping arithmetic");
        assert_eq!(ctx.n_mem(), i32::MIN);
    }

    #[test]
    fn shipped_default_reports_not_cached_and_is_a_noop() {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(TEMP_REG_OPS), DEFAULT_TEMP_REG_OPS);
            let op = used_as_column_cache_op();
            assert_eq!(op(core::ptr::null_mut(), 7, 7), 0);
        }
        let mut ctx = ParseContext::new(2, &[9, 10], 50);
        let reg = unsafe { get_temp_reg(ctx.ptr()) };
        assert_eq!(reg, 51);
        assert_eq!(ctx.n_mem(), 51);
        assert_eq!(ctx.count(), 2);
        drop(ops_guard);
    }
}
