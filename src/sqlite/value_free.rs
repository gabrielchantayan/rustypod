//! The value destructor — how the VDBE destroys a P4 value payload (an
//! `sqlite3_value`/`Mem`).
//!
//! - `value_free` — original: `FUN_08386504` @ 0x08386504 (32 bytes;
//!   4 `bl` + 1 tail `b` call sites: the -8 branch of `vdbe_free_p4`
//!   @ 0x082cf388 tail-calls it, and the column-name / error-message
//!   teardowns @ 0x082beac8, 0x0836ed14, 0x083866ac and 0x0838feec call
//!   it directly). Upstream SQLite's `sqlite3ValueFree`.
//!
//! Algorithm: three steps. A NULL value returns immediately
//! (`movs r4,r0` / `ldmiaeq`). Otherwise the value's dynamic guts are
//! released by `sqlite3VdbeMemRelease` @ 0x0838c04c (`bl` — that helper
//! finalizes an aggregate context (flags bit 0x400 at +0x1c) or invokes
//! the `xDel` destructor at +0x20 (flags bit 0x40), frees `zMalloc`
//! (+0x24), and NULLs `z` +0x14 / `xDel` +0x20 / `zMalloc` +0x24), then
//! the `Mem` shell itself is freed — the original's tail branch
//! `b sqlite3_free` @ 0x083906f4, here [`tracked_free`].
//!
//! Deviations:
//! - `sqlite3VdbeMemRelease` @ 0x0838c04c is NOT ported; it is the
//!   [`VALUE_MEM_OPS`] dispatch boundary (house pattern — see
//!   `heap/block_region.rs`, `sqlite/mem.rs`). Its default slot is a
//!   documented no-op: an unconfigured build frees the shell and leaks
//!   the guts rather than running the wrong destructor (the same
//!   "leak rather than corrupt" stance the `missing_destructor` stub
//!   this port replaces took for the whole payload).
//! - `sqlite3_free` @ 0x083906f4 IS ported
//!   ([`tracked_free`](crate::heap::tracked::tracked_free)) and is
//!   called directly, per the porting rules.
//! - Ghidra's C for the original inlines the whole tag-57 free after
//!   the `bl 0x0838c04c` — that is the tail-called `sqlite3_free`
//!   body, not code owned by this function (its 32 bytes end at the
//!   `b 0x083906f4`).

use crate::heap::tracked::tracked_free;

/// Indirect dispatch for the unported guts release @ 0x0838c04c
/// (kept behind the table so host tests can intercept it).
#[derive(Clone, Copy)]
pub struct ValueMemOps {
    /// `sqlite3VdbeMemRelease(value)` @ 0x0838c04c: release the value's
    /// dynamic resources (aggregate context / `xDel` destructor /
    /// `zMalloc`) without freeing the shell. NULL-tolerant only in the
    /// sense that [`value_free`] never calls it with NULL.
    pub mem_release: unsafe extern "C" fn(value: *mut u8),
}

/// Default stub: the guts are leaked, not released (see the module
/// header). Deliberately not a passthrough to a raw free — the guts of
/// a `Mem` are reached through type-tagged pointers and destructors,
/// and guessing wrong corrupts.
unsafe extern "C" fn missing_mem_release(_value: *mut u8) {}

/// Wired defaults: the one unported helper is a documented no-op.
pub const DEFAULT_VALUE_MEM_OPS: ValueMemOps = ValueMemOps { mem_release: missing_mem_release };

/// The active guts release. Host tests install recording mocks; the
/// real port replaces the default when 0x0838c04c lands.
pub static mut VALUE_MEM_OPS: ValueMemOps = DEFAULT_VALUE_MEM_OPS;

/// Reads the mem-release slot (volatile — the slot is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) unsafe fn mem_release_op() -> unsafe extern "C" fn(*mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(VALUE_MEM_OPS.mem_release))
}

/// value_free — original: `FUN_08386504` @ 0x08386504 (32 bytes).
///
/// `sqlite3ValueFree`: destroy the value `value`. NULL returns before
/// anything is touched; otherwise the value's dynamic guts go to the
/// mem-release helper @ 0x0838c04c (the [`VALUE_MEM_OPS`] slot) and
/// the shell is freed raw through the tag-57 tracked allocator — the
/// original's `mov r0,r4; ldmia sp!,{r4,lr}; b sqlite3_free` tail.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn value_free(value: *mut u8) {
    if value.is_null() {
        return;
    }
    (mem_release_op())(value);
    // Original: `b sqlite3_free` — a tail call.
    tracked_free(value);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the mem-release slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every destructor/free the code under test triggered, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        MemRelease(usize),
        RawFree(usize, usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();

    unsafe extern "C" fn recording_mem_release(value: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::MemRelease(value as usize));
    }

    unsafe extern "C" fn recording_heap_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::RawFree(ptr as usize, tag));
    }

    /// Installs the mock heap (first — the lock order `error_msg`'s
    /// tests establish), routes frees into the event log, and installs
    /// the recording guts release. The guards must stay alive for the
    /// whole test.
    fn bench() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let heap_guard = mock_heap();
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VALUE_MEM_OPS),
                ValueMemOps { mem_release: recording_mem_release },
            );
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
        }
        (heap_guard, ops_guard)
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// A hand-built tag-57 tracked block whose payload plays the `Mem`
    /// shell (layout: `heap::tracked`). Raw block at offset 0 of a
    /// 32-aligned buffer, payload at raw + 32, pad word 32 - 8 = 24.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new() -> Self {
            let mut block = TrackedBlock([0; 64]);
            block.0[0..4].copy_from_slice(&24i32.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }
        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn payload(&mut self) -> *mut u8 {
            // In-bounds by construction (64-byte block, payload at 32).
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    #[test]
    fn a_null_value_is_never_read_nor_freed() {
        let _guards = bench();
        unsafe { value_free(core::ptr::null_mut()) };
        assert!(events().is_empty());
    }

    #[test]
    fn a_value_releases_its_guts_then_frees_the_shell_with_tag_fifty_seven() {
        let _guards = bench();
        let mut block = TrackedBlock::new();
        let raw = block.raw();
        let payload = block.payload();
        unsafe { value_free(payload) };
        assert_eq!(
            events(),
            std::vec![
                Event::MemRelease(payload as usize),
                Event::RawFree(raw as usize, TAG_TRACKED),
            ],
            "guts release first, shell free second — the original's bl-then-b order"
        );
    }

    #[test]
    fn the_default_free_p4_slot_is_this_function() {
        use crate::sqlite::free_p4::DEFAULT_FREE_P4_AUX_OPS;
        assert_eq!(
            DEFAULT_FREE_P4_AUX_OPS.value_free as usize,
            value_free as usize,
            "vdbe_free_p4's -8 branch reaches the ported destructor by default"
        );
    }
}
