//! Port of the D-cache clean+invalidate range walk that `pool_alloc`
//! (heap/pool.rs) runs for uncached (DMA-coherent) allocations, plus the
//! per-line CP15 primitive it is built on:
//!
//! - `dcache_line_clean_invalidate` — original: `FUN_08037cd0`
//!   @ 0x08037cd0 (8 bytes): `mcr p15,0,r0,cr7,cr14,1; bx lr` — the
//!   ARM926EJ-S "clean and invalidate D-cache single entry (MVA)" op.
//!   Sole `bl` caller is the range walk below.
//! - `dcache_clean_invalidate` — original: `FUN_08044c10` @ 0x08044c10
//!   (56 bytes; 22 `bl` call sites — DMA buffer prep across the ATA/USB/
//!   LCD drivers, plus `pool_alloc`'s uncached path via the POOL_OPS
//!   `dcache_flush` slot). If bit 31 of `addr` is set (the S5L8702
//!   uncached DRAM alias — the data never entered the cache) it returns
//!   immediately. Otherwise it walks `off = 0, 0x20, ...` while
//!   `off < len`, cleaning+invalidating the 32-byte line at
//!   `(addr + off) & !0x1f` each step.
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
//! The per-line op is the [`DCACHE_LINE_OP`] dispatch slot (the
//! SEMIHOST_SWI pattern of stdio/semihost.rs), whose default
//! [`dcache_line_clean_invalidate`] is cfg-gated:
//!
//! - On the firmware target (`target_os = "none"`, ARM) it issues the
//!   real `mcr p15, 0, {r}, c7, c14, 1` — bit-faithful to 0x08037cd0.
//! - On hosts there is no CP15, and a cache-maintenance op has, by
//!   definition, no architecturally visible effect on memory contents —
//!   the default is a no-op. Host tests install a recording mock and
//!   prove the *walk*: which line addresses get flushed, the alignment
//!   masking, the bit-31 early exit, and the len-0 edge. They prove
//!   nothing about actual cache coherency — that property only exists
//!   on target, through the real `mcr`.
//!
//! The range walk reaches the line op through the slot (indirect call)
//! instead of the original's direct `bl 0x08037cd0`; codegen deviates in
//! exactly that one instruction, as with every other dispatch-slot port.

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
}
