//! Port of the D-cache clean+invalidate range walk that `pool_alloc`
//! (heap/pool.rs) runs for uncached (DMA-coherent) allocations, its
//! clean-only sibling used by the display-layer flush paths, plus the
//! per-line CP15 primitives they are built on:
//!
//! - `dcache_line_clean_invalidate` — original: `FUN_08037cd0`
//!   @ 0x08037cd0 (8 bytes): `mcr p15,0,r0,cr7,cr14,1; bx lr` — the
//!   ARM926EJ-S "clean and invalidate D-cache single entry (MVA)" op.
//!   Sole `bl` caller is the clean+invalidate range walk below.
//! - `dcache_line_clean` — original: `FUN_08037cc8` @ 0x08037cc8
//!   (8 bytes): `mcr p15,0,r0,cr7,cr10,1; bx lr` — the "clean D-cache
//!   single entry (MVA)" op (no invalidate). Sole `bl` caller is the
//!   clean-only range walk below.
//! - `dcache_clean_all` — original: `FUN_08037cd8` @ 0x08037cd8
//!   (52 bytes): cleans the ENTIRE data cache by set/way — an inner
//!   index sweep (r0 = 0, 0x20, ... < 0x1000; 128 sets at the 32-byte
//!   line stride) inside an outer way sweep (r1 stepped 0x2000_0000
//!   until it wraps to zero; 8 passes) of `mcr p15,0,(r1|r0),c7,c10,2`
//!   — 1024 set/way cleans in all — then drains the write buffer
//!   (`mcr p15,0,r0,c7,c10,4` with r0 = 0, which is also the return
//!   value). Sole `bl` caller: FUN_0836a990 @ 0x0836aa94. Its sibling
//!   @ 0x08037d0c is the same sweep with clean+invalidate (c7,c14,2).
//! - `dcache_clean_invalidate` — original: `FUN_08044c10` @ 0x08044c10
//!   (56 bytes; 22 `bl` call sites — DMA buffer prep across the ATA/USB/
//!   LCD drivers, plus `pool_alloc`'s uncached path via the POOL_OPS
//!   `dcache_flush` slot). If bit 31 of `addr` is set (the S5L8702
//!   uncached DRAM alias — the data never entered the cache) it returns
//!   immediately. Otherwise it walks `off = 0, 0x20, ...` while
//!   `off < len`, cleaning+invalidating the 32-byte line at
//!   `(addr + off) & !0x1f` each step.
//! - `dcache_clean` — original: `FUN_08044c48` @ 0x08044c48 (48 bytes;
//!   6 `bl` call sites — the display-layer plane/surface flushes in
//!   layer_install_planes @ 0x0811feb8 and friends). The same
//!   line walk as `dcache_clean_invalidate` but *clean-only* (per-line
//!   `bl 0x08037cc8`) and with *no bit-31 guard* — callers that may
//!   hand it an uncached-alias pointer test bit 31 themselves (e.g.
//!   layer_install_planes' `tst` on p0).
//!
//! Original-quirk, kept: the walk steps from `addr`, not from the aligned
//! line start, so a misaligned `addr` whose byte range spills into one
//! more line than `len / 0x20` covers leaves the final line untouched
//! (e.g. addr 0x1c, len 0x20 flushes only line 0x00, not line 0x20).
//! Callers compensate by passing padded lengths (`pool_alloc` flushes
//! `ptr - 4` for `size + 4` bytes).
//!
//! # The CP15 hardware boundary (deviation, by necessity)
//!
//! The per-line ops are the [`DCACHE_LINE_OP`] / [`DCACHE_CLEAN_LINE_OP`]
//! dispatch slots (the SEMIHOST_SWI pattern of stdio/semihost.rs), whose
//! defaults [`dcache_line_clean_invalidate`] / [`dcache_line_clean`] are
//! cfg-gated:
//!
//! - On the firmware target (`target_os = "none"`, ARM) they issue the
//!   real `mcr p15, 0, {r}, c7, c14, 1` / `mcr p15, 0, {r}, c7, c10, 1` —
//!   bit-faithful to 0x08037cd0 / 0x08037cc8.
//! - On hosts there is no CP15, and a cache-maintenance op has, by
//!   definition, no architecturally visible effect on memory contents —
//!   the default is a no-op. Host tests install a recording mock and
//!   prove the *walk*: which line addresses get flushed, the alignment
//!   masking, the bit-31 early exit, and the len-0 edge. They prove
//!   nothing about actual cache coherency — that property only exists
//!   on target, through the real `mcr`.
//!
//! The range walks reach the line op through the slots (indirect call)
//! instead of the originals' direct `bl 0x08037cd0` / `bl 0x08037cc8`;
//! codegen deviates in exactly that one instruction, as with every other
//! dispatch-slot port. `dcache_clean_all` likewise reaches its two CP15
//! ops (the set/way clean and the write-buffer drain, neither of which
//! is a standalone firmware function) through the
//! [`DCACHE_SET_WAY_CLEAN_OP`] / [`DCACHE_DRAIN_WRITE_BUFFER_OP`] slots.

/// The per-line boundary: clean+invalidate the D-cache line containing
/// `mva` (a 32-byte-aligned modified virtual address on target).
pub type DcacheLineFn = unsafe extern "C" fn(mva: usize);

/// D-cache line size on the ARM926EJ-S (the original's `#0x20` stride and
/// `#0x1f` mask).
pub const DCACHE_LINE_SIZE: usize = 0x20;

/// Bit 31: the S5L8702 uncached DRAM alias marker (same constant as
/// pool.rs's `UNCACHED_MARK`).
const UNCACHED_BIT: usize = 0x8000_0000;

/// dcache_line_clean_invalidate — original: `FUN_08037cd0` @ 0x08037cd0
/// (8 bytes).
///
/// Firmware target: the real CP15 op, `mcr p15,0,{mva},c7,c14,1` (clean
/// and invalidate D-cache single entry by MVA).
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dcache_line_clean_invalidate(mva: usize) {
    core::arch::asm!(
        "mcr p15, 0, {0}, c7, c14, 1",
        in(reg) mva,
        options(nostack, preserves_flags),
    );
}

/// dcache_line_clean_invalidate — original: `FUN_08037cd0` @ 0x08037cd0
/// (8 bytes).
///
/// Host stand-in: no CP15 exists, and the real op does not change memory
/// contents — no-op. Tests install a recording mock via
/// [`DCACHE_LINE_OP`] instead (see the module header for what that does
/// and does not prove).
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
pub unsafe extern "C" fn dcache_line_clean_invalidate(_mva: usize) {}

/// The active per-line implementation: the real `mcr` on the firmware
/// target, a no-op on hosts (tests install recording mocks here).
pub static mut DCACHE_LINE_OP: DcacheLineFn = dcache_line_clean_invalidate;

/// Reads the line-op slot. Volatile so a build in which nothing rewrites
/// the slot cannot constant-fold the default in and delete the dispatch
/// (the slot is meant to be swapped at runtime).
#[inline(always)]
fn dcache_line_op() -> DcacheLineFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DCACHE_LINE_OP)) }
}

/// dcache_line_clean — original: `FUN_08037cc8` @ 0x08037cc8 (8 bytes).
///
/// Firmware target: the real CP15 op, `mcr p15,0,{mva},c7,c10,1` (clean
/// D-cache single entry by MVA — no invalidate).
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dcache_line_clean(mva: usize) {
    core::arch::asm!(
        "mcr p15, 0, {0}, c7, c10, 1",
        in(reg) mva,
        options(nostack, preserves_flags),
    );
}

/// dcache_line_clean — original: `FUN_08037cc8` @ 0x08037cc8 (8 bytes).
///
/// Host stand-in: no CP15 exists, and the real op does not change memory
/// contents — no-op. Tests install a recording mock via
/// [`DCACHE_CLEAN_LINE_OP`] instead (see the module header for what that
/// does and does not prove).
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
pub unsafe extern "C" fn dcache_line_clean(_mva: usize) {}

/// The active per-line clean implementation: the real `mcr` on the
/// firmware target, a no-op on hosts (tests install recording mocks
/// here). Kept separate from [`DCACHE_LINE_OP`] because the two walks
/// must stay distinguishable in recordings — clean-only vs
/// clean+invalidate is exactly the difference between 0x08044c48 and
/// 0x08044c10.
pub static mut DCACHE_CLEAN_LINE_OP: DcacheLineFn = dcache_line_clean;

/// Reads the clean line-op slot (same volatile rationale as
/// [`dcache_line_op`]).
#[inline(always)]
fn dcache_clean_line_op() -> DcacheLineFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DCACHE_CLEAN_LINE_OP)) }
}

/// dcache_clean_invalidate — original: `FUN_08044c10` @ 0x08044c10
/// (56 bytes).
///
/// Cleans+invalidates every D-cache line the walk touches in
/// `[addr, addr + len)` (see the module header for the misalignment
/// quirk). Returns immediately when `addr` already carries the bit-31
/// uncached alias. `len == 0` flushes nothing.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dcache_clean_invalidate(addr: *mut u8, len: usize) {
    if addr as usize & UNCACHED_BIT != 0 {
        return;
    }
    let line_op = dcache_line_op();
    let mut off = 0;
    while off < len {
        line_op((addr as usize).wrapping_add(off) & !(DCACHE_LINE_SIZE - 1));
        off += DCACHE_LINE_SIZE;
    }
}

/// dcache_clean — original: `FUN_08044c48` @ 0x08044c48 (48 bytes).
///
/// Cleans (without invalidating) every D-cache line the walk touches in
/// `[addr, addr + len)`, per line via `bl 0x08037cc8` (here the
/// [`DCACHE_CLEAN_LINE_OP`] slot). Unlike [`dcache_clean_invalidate`]
/// there is *no bit-31 uncached-alias guard* — the original walks the
/// given address verbatim, so callers that may hold an alias pointer
/// guard it themselves (layer_install_planes' `tst` on p0). Same
/// original-quirk walk semantics as the sibling: steps from `addr`, not
/// the aligned line start; `len == 0` flushes nothing.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dcache_clean(addr: *mut u8, len: usize) {
    let line_op = dcache_clean_line_op();
    let mut off = 0;
    while off < len {
        line_op((addr as usize).wrapping_add(off) & !(DCACHE_LINE_SIZE - 1));
        off += DCACHE_LINE_SIZE;
    }
}

/// The set/way boundary: clean the D-cache line selected by the set/way
/// `operand` (the original's `orr r2, r1, r0` of the way accumulator and
/// the line index), or — for the trailing write-buffer drain — ignore a
/// zero operand.
pub type DcacheSetWayFn = unsafe extern "C" fn(operand: u32);

/// Inner index span of the set/way sweep: 0x1000 = 128 sets at the
/// 0x20 line stride (the original's `cmp r0, #0x1000`).
const DCACHE_SET_SPAN: u32 = 0x1000;

/// Outer way-accumulator step: 0x2000_0000 per pass, wrapping to zero
/// after 8 passes (the original's `add r1, r1, #0x20000000; cmp r1, #0`).
const DCACHE_WAY_STEP: u32 = 0x2000_0000;

/// The set/way clean primitive inside the original's inner loop — not a
/// standalone firmware function.
///
/// Firmware target: the real CP15 op, `mcr p15,0,{operand},c7,c10,2`
/// (clean D-cache single entry by set/way — no invalidate).
#[cfg(all(target_os = "none", target_arch = "arm"))]
unsafe extern "C" fn dcache_set_way_clean(operand: u32) {
    core::arch::asm!(
        "mcr p15, 0, {0}, c7, c10, 2",
        in(reg) operand,
        options(nostack, preserves_flags),
    );
}

/// Host stand-in: no CP15 exists, and the real op does not change memory
/// contents — no-op. Tests install a recording mock via
/// [`DCACHE_SET_WAY_CLEAN_OP`] instead (see the module header for what
/// that does and does not prove).
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
unsafe extern "C" fn dcache_set_way_clean(_operand: u32) {}

/// The active set/way clean implementation: the real `mcr` on the
/// firmware target, a no-op on hosts (tests install recording mocks
/// here).
pub static mut DCACHE_SET_WAY_CLEAN_OP: DcacheSetWayFn = dcache_set_way_clean;

/// Reads the set/way clean slot (same volatile rationale as
/// [`dcache_line_op`]).
#[inline(always)]
fn dcache_set_way_clean_op() -> DcacheSetWayFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DCACHE_SET_WAY_CLEAN_OP)) }
}

/// The write-buffer drain the original runs after the sweep — not a
/// standalone firmware function.
///
/// Firmware target: the real CP15 op, `mcr p15,0,{operand},c7,c10,4`
/// (ARMv5 drain write buffer; Ghidra labels it "Data Synchronization"),
/// always with operand 0.
#[cfg(all(target_os = "none", target_arch = "arm"))]
unsafe extern "C" fn dcache_drain_write_buffer(operand: u32) {
    core::arch::asm!(
        "mcr p15, 0, {0}, c7, c10, 4",
        in(reg) operand,
        options(nostack, preserves_flags),
    );
}

/// Host stand-in: no CP15 exists — no-op. Tests install a recording mock
/// via [`DCACHE_DRAIN_WRITE_BUFFER_OP`] instead.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
unsafe extern "C" fn dcache_drain_write_buffer(_operand: u32) {}

/// The active write-buffer drain implementation: the real `mcr` on the
/// firmware target, a no-op on hosts (tests install recording mocks
/// here). Kept separate from [`DCACHE_SET_WAY_CLEAN_OP`] so recordings
/// prove the drain's trailing position in the sweep.
pub static mut DCACHE_DRAIN_WRITE_BUFFER_OP: DcacheSetWayFn = dcache_drain_write_buffer;

/// Reads the write-buffer drain slot (same volatile rationale as
/// [`dcache_line_op`]).
#[inline(always)]
fn dcache_drain_write_buffer_op() -> DcacheSetWayFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DCACHE_DRAIN_WRITE_BUFFER_OP)) }
}

/// dcache_clean_all — original: `FUN_08037cd8` @ 0x08037cd8 (52 bytes).
///
/// Cleans the ENTIRE data cache by set/way, then drains the write buffer
/// and returns 0. The original sweeps an inner index r0 = 0, 0x20, ...
/// < 0x1000 (128 sets at the 32-byte line stride) inside an outer way
/// accumulator r1 stepped by 0x2000_0000 until it wraps to zero (8
/// passes), issuing `mcr p15,0,(r1|r0),c7,c10,2` — 1024 set/way cleans
/// in all — then `mov r0, #0; mcr p15,0,r0,c7,c10,4; bx lr`, so the
/// drain's zero operand doubles as the return value. Sole `bl` caller:
/// FUN_0836a990 @ 0x0836aa94. The clean+invalidate sibling sweep sits
/// right after @ 0x08037d0c (c7,c14,2).
///
/// The two CP15 ops go through the [`DCACHE_SET_WAY_CLEAN_OP`] and
/// [`DCACHE_DRAIN_WRITE_BUFFER_OP`] slots (the module-header deviation):
/// real `mcr`s on the firmware target, recording mocks in host tests —
/// which prove the sweep's exact operand sequence and the drain's
/// trailing position, not cache coherency.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dcache_clean_all() -> u32 {
    let set_way_clean = dcache_set_way_clean_op();
    let drain_write_buffer = dcache_drain_write_buffer_op();
    let mut way = 0u32;
    loop {
        let mut index = 0u32;
        loop {
            set_way_clean(way | index);
            index = index.wrapping_add(DCACHE_LINE_SIZE as u32);
            if index == DCACHE_SET_SPAN {
                break;
            }
        }
        way = way.wrapping_add(DCACHE_WAY_STEP);
        if way == 0 {
            break;
        }
    }
    drain_write_buffer(0);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the global line-op slot.
    static OP_LOCK: Mutex<()> = Mutex::new(());

    /// Line addresses the recording mock saw, in call order.
    static mut FLUSHED: Vec<usize> = Vec::new();

    unsafe extern "C" fn recording_line_op(mva: usize) {
        (*core::ptr::addr_of_mut!(FLUSHED)).push(mva);
    }

    /// Locks the slot, installs the recording mock, clears the log.
    fn mock_line_op() -> MutexGuard<'static, ()> {
        let guard = OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            DCACHE_LINE_OP = recording_line_op;
            (*core::ptr::addr_of_mut!(FLUSHED)).clear();
        }
        guard
    }

    /// Restores the default (no-op host) line op. Call before dropping
    /// the guard.
    fn restore_line_op() {
        unsafe { DCACHE_LINE_OP = dcache_line_clean_invalidate };
    }

    fn flushed() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(FLUSHED)).clone() }
    }

    #[test]
    fn aligned_range_flushes_every_line_once() {
        let _guard = mock_line_op();
        unsafe { dcache_clean_invalidate(0x1000 as *mut u8, 0x80) };
        assert_eq!(flushed(), std::vec![0x1000, 0x1020, 0x1040, 0x1060]);
        restore_line_op();
    }

    #[test]
    fn misaligned_addr_masks_to_line_start() {
        let _guard = mock_line_op();
        // pool_alloc's actual shape: ptr - 4 for size + 4.
        unsafe { dcache_clean_invalidate(0x201c as *mut u8, 0x24) };
        // off 0 -> line 0x2000, off 0x20 -> line 0x2020 (0x203c & !0x1f).
        assert_eq!(flushed(), std::vec![0x2000, 0x2020]);
        restore_line_op();
    }

    #[test]
    fn walk_steps_from_addr_not_line_start() {
        let _guard = mock_line_op();
        // Original quirk: addr 0x1c, len 0x20 touches bytes up to 0x3b
        // but the walk stops after one step — line 0x20 stays unflushed.
        unsafe { dcache_clean_invalidate(0x1c as *mut u8, 0x20) };
        assert_eq!(flushed(), std::vec![0x0]);
        restore_line_op();
    }

    #[test]
    fn zero_len_flushes_nothing() {
        let _guard = mock_line_op();
        unsafe { dcache_clean_invalidate(0x4000 as *mut u8, 0) };
        assert!(flushed().is_empty());
        restore_line_op();
    }

    #[test]
    fn partial_line_still_flushes_its_line() {
        let _guard = mock_line_op();
        unsafe { dcache_clean_invalidate(0x3000 as *mut u8, 1) };
        assert_eq!(flushed(), std::vec![0x3000]);
        restore_line_op();
    }

    #[test]
    fn uncached_alias_returns_without_flushing() {
        let _guard = mock_line_op();
        unsafe { dcache_clean_invalidate(0x8800_1000usize as *mut u8, 0x100) };
        assert!(flushed().is_empty(), "bit-31 alias must early-exit");
        restore_line_op();
    }

    #[test]
    fn default_host_line_op_is_a_noop() {
        let _guard = OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_line_op();
        // Nothing observable to assert beyond "returns without effect".
        unsafe { dcache_clean_invalidate(0x1000 as *mut u8, 0x40) };
    }

    // ---- dcache_clean (0x08044c48, clean-only, no bit-31 guard) ----

    /// Line addresses the clean-only recording mock saw, in call order.
    static mut CLEAN_FLUSHED: Vec<usize> = Vec::new();

    unsafe extern "C" fn recording_clean_line_op(mva: usize) {
        (*core::ptr::addr_of_mut!(CLEAN_FLUSHED)).push(mva);
    }

    /// Locks the slot, installs the clean recording mock, clears the log.
    fn mock_clean_line_op() -> MutexGuard<'static, ()> {
        let guard = OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            DCACHE_CLEAN_LINE_OP = recording_clean_line_op;
            (*core::ptr::addr_of_mut!(CLEAN_FLUSHED)).clear();
        }
        guard
    }

    /// Restores the default (no-op host) clean line op.
    fn restore_clean_line_op() {
        unsafe { DCACHE_CLEAN_LINE_OP = dcache_line_clean };
    }

    fn clean_flushed() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(CLEAN_FLUSHED)).clone() }
    }

    #[test]
    fn clean_aligned_range_flushes_every_line_once() {
        let _guard = mock_clean_line_op();
        unsafe { dcache_clean(0x1000 as *mut u8, 0x80) };
        assert_eq!(clean_flushed(), std::vec![0x1000, 0x1020, 0x1040, 0x1060]);
        restore_clean_line_op();
    }

    #[test]
    fn clean_misaligned_addr_masks_to_line_start() {
        let _guard = mock_clean_line_op();
        unsafe { dcache_clean(0x201c as *mut u8, 0x24) };
        assert_eq!(clean_flushed(), std::vec![0x2000, 0x2020]);
        restore_clean_line_op();
    }

    #[test]
    fn clean_walk_steps_from_addr_not_line_start() {
        let _guard = mock_clean_line_op();
        // Same quirk as the sibling: addr 0x1c, len 0x20 stops after one
        // step — line 0x20 stays unflushed.
        unsafe { dcache_clean(0x1c as *mut u8, 0x20) };
        assert_eq!(clean_flushed(), std::vec![0x0]);
        restore_clean_line_op();
    }

    #[test]
    fn clean_zero_len_flushes_nothing() {
        let _guard = mock_clean_line_op();
        unsafe { dcache_clean(0x4000 as *mut u8, 0) };
        assert!(clean_flushed().is_empty());
        restore_clean_line_op();
    }

    #[test]
    fn clean_partial_line_still_flushes_its_line() {
        let _guard = mock_clean_line_op();
        unsafe { dcache_clean(0x3000 as *mut u8, 1) };
        assert_eq!(clean_flushed(), std::vec![0x3000]);
        restore_clean_line_op();
    }

    #[test]
    fn clean_uncached_alias_is_flushed_anyway() {
        let _guard = mock_clean_line_op();
        // The defining difference from 0x08044c10: no bit-31 early exit.
        // The original walks the alias address verbatim (the masking
        // keeps bit 31, so the recorded mvas carry it).
        unsafe { dcache_clean(0x8800_1000usize as *mut u8, 0x40) };
        assert_eq!(clean_flushed(), std::vec![0x8800_1000, 0x8800_1020]);
        restore_clean_line_op();
    }

    #[test]
    fn clean_default_host_line_op_is_a_noop() {
        let _guard = OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_clean_line_op();
        // Nothing observable to assert beyond "returns without effect".
        unsafe { dcache_clean(0x1000 as *mut u8, 0x40) };
    }

    // ---- dcache_clean_all (0x08037cd8, set/way sweep + drain) ----

    /// Operation tags in the order the sweep records them.
    const SET_WAY_CLEAN: u32 = 0;
    const DRAIN_WRITE_BUFFER: u32 = 1;

    /// (tag, operand) pairs the recording mocks saw, in call order.
    static mut SWEEP_LOG: Vec<(u32, u32)> = Vec::new();

    unsafe extern "C" fn recording_set_way_clean(operand: u32) {
        (*core::ptr::addr_of_mut!(SWEEP_LOG)).push((SET_WAY_CLEAN, operand));
    }

    unsafe extern "C" fn recording_drain_write_buffer(operand: u32) {
        (*core::ptr::addr_of_mut!(SWEEP_LOG)).push((DRAIN_WRITE_BUFFER, operand));
    }

    /// Locks the slots, installs both recording mocks, clears the log.
    fn mock_sweep_ops() -> MutexGuard<'static, ()> {
        let guard = OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            DCACHE_SET_WAY_CLEAN_OP = recording_set_way_clean;
            DCACHE_DRAIN_WRITE_BUFFER_OP = recording_drain_write_buffer;
            (*core::ptr::addr_of_mut!(SWEEP_LOG)).clear();
        }
        guard
    }

    /// Restores the default (no-op host) ops. Call before dropping the
    /// guard.
    fn restore_sweep_ops() {
        unsafe {
            DCACHE_SET_WAY_CLEAN_OP = dcache_set_way_clean;
            DCACHE_DRAIN_WRITE_BUFFER_OP = dcache_drain_write_buffer;
        }
    }

    fn sweep_log() -> Vec<(u32, u32)> {
        unsafe { (*core::ptr::addr_of!(SWEEP_LOG)).clone() }
    }

    /// Reference sequence straight from the original's loops: inner
    /// index 0, 0x20, ... < 0x1000 ORed into an outer way accumulator
    /// stepped 0x2000_0000 until wrap, then one drain of 0.
    fn expected_sweep() -> Vec<(u32, u32)> {
        let mut expected = Vec::new();
        let mut way = 0u32;
        loop {
            let mut index = 0u32;
            loop {
                expected.push((SET_WAY_CLEAN, way | index));
                index = index.wrapping_add(0x20);
                if index == 0x1000 {
                    break;
                }
            }
            way = way.wrapping_add(0x2000_0000);
            if way == 0 {
                break;
            }
        }
        expected.push((DRAIN_WRITE_BUFFER, 0));
        expected
    }

    #[test]
    fn sweep_matches_the_originals_operand_sequence_and_returns_zero() {
        let _guard = mock_sweep_ops();
        let returned = unsafe { dcache_clean_all() };
        assert_eq!(returned, 0, "the drain's zero operand doubles as r0");
        assert_eq!(sweep_log(), expected_sweep());
        restore_sweep_ops();
    }

    #[test]
    fn sweep_boundaries_cover_every_set_and_way_pass() {
        let _guard = mock_sweep_ops();
        unsafe { dcache_clean_all() };
        let log = sweep_log();
        // 8 way passes x 128 sets, then exactly one drain.
        assert_eq!(log.len(), 8 * 128 + 1);
        assert_eq!(log[0], (SET_WAY_CLEAN, 0));
        assert_eq!(log[8 * 128 - 1], (SET_WAY_CLEAN, 0xe000_0fe0));
        assert_eq!(log[8 * 128], (DRAIN_WRITE_BUFFER, 0));
        // Way passes restart the index at zero.
        assert_eq!(log[128], (SET_WAY_CLEAN, 0x2000_0000));
        restore_sweep_ops();
    }

    #[test]
    fn sweep_default_host_ops_are_noops() {
        let _guard = OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_sweep_ops();
        // Nothing observable beyond returning 0 without effect.
        assert_eq!(unsafe { dcache_clean_all() }, 0);
    }
}
