//! The P4 payload destructor — how the VDBE releases the fourth operand
//! of an op when the op is overwritten or torn down.
//!
//! - `vdbe_free_p4` — original: `FUN_082cf388` @ 0x082cf388 (148 bytes;
//!   2 `bl` + 2 tail `b` call sites, all inside `vdbe_change_p4` /
//!   `vdbe_add_op4` territory plus the op-array teardown). SQLite's
//!   `freeP4`.
//!
//! Algorithm: a NULL payload returns immediately (`cmp r1,#0` /
//! `ldmiaeq`). Otherwise a jump table over `p4type` shifted by +13
//! (`add r0,r0,#0xd; cmp r0,#0xc; addls pc,pc,r0,lsl#2`) dispatches on
//! tags -13..=0:
//!
//! - -13 / -12 / -11 / -9 / -6 / -1: free the pointer raw — a shared
//!   tail branch to `sqlite3_free` @ 0x083906f4 (`mov r0,r1; b`).
//! - -10 / -4 / -3 / -2: return, payload untouched.
//! - -8: tail-call the value destructor @ 0x08386504 (NULL-guards,
//!   releases the value's guts @ 0x0838c04c, frees the shell).
//! - -7: release an ephemeral function @ 0x082cf358 on the payload's
//!   first word (`ldr r0,[r1]`), sweep the payload's (arg, destructor)
//!   record array @ 0x08386e08 with mask 0, then free the payload raw.
//! - -5: tail-call the ephemeral-function release @ 0x082cf358 on the
//!   payload itself.
//! - anything outside -13..=0 (e.g. `P4_ADVANCE` == -14, see
//!   [`sqlite::vdbe`](crate::sqlite::vdbe)): return unfreed (the
//!   `addls` falls through to `ldmia sp!,{r4,pc}`).
//!
//! Deviations:
//! - `sqlite3_free` @ 0x083906f4 IS ported
//!   ([`tracked_free`](crate::heap::tracked::tracked_free)) and is
//!   called directly, per the porting rules.
//! - The value destructor @ 0x08386504 IS ported
//!   ([`sqlite::value_free`](crate::sqlite::value_free)) and is the
//!   default `value_free` slot; its own guts-release dependency
//!   @ 0x0838c04c rides that module's `VALUE_MEM_OPS` slot. The
//!   ephemeral-function release @ 0x082cf358 IS ported
//!   ([`sqlite::ephemeral_fn`](crate::sqlite::ephemeral_fn)) and is the
//!   default `free_ephemeral_function` slot. The record-array sweep
//!   @ 0x08386e08 IS ported ([`sqlite::aux_sweep`](crate::sqlite::aux_sweep))
//!   and is the default `context_aux_cleanup` slot.
//! - `vdbe_change_p4` keeps reaching this function through its own
//!   `VDBE_P4_OPS` slot; wiring that slot to [`vdbe_free_p4`] is left
//!   to the commit that flips the default.

use crate::heap::tracked::tracked_free;
use crate::sqlite::aux_sweep::vdbe_context_aux_sweep;
use crate::sqlite::ephemeral_fn::free_ephemeral_function;
use crate::sqlite::value_free::value_free;
use crate::sqlite::vdbe::{P4_DYNAMIC, P4_KEYINFO, P4_KEYINFO_HANDOFF};

/// Tag -8: the payload is a value released by the destructor @
/// 0x08386504 (upstream SQLite's `P4_MEM` role — `sqlite3ValueFree`).
pub const P4_VALUE: i32 = -8;
/// Tag -7: the payload is a function context whose first word is a
/// `FuncDef` (released ephemerally) followed by an aux-record array.
pub const P4_FUNCCTX: i32 = -7;
/// Tag -5: the payload is itself a function definition released by the
/// ephemeral-function check @ 0x082cf358 (upstream's `P4_FUNCDEF`).
pub const P4_FUNCDEF: i32 = -5;

/// Indirect dispatch for the value destructor @ 0x08386504, plus the
/// ported ephemeral-function release @ 0x082cf358 and record-array
/// sweep @ 0x08386e08 (kept behind the table so host tests can
/// intercept them).
#[derive(Clone, Copy)]
pub struct FreeP4AuxOps {
    /// Value destructor @ 0x08386504: release a value payload (tag
    /// [`P4_VALUE`]). NULL-tolerant itself. Ported — the default is
    /// [`value_free`](crate::sqlite::value_free::value_free).
    pub value_free: unsafe extern "C" fn(p4: *mut u8),
    /// Ephemeral-function release @ 0x082cf358: free the `FuncDef` only
    /// when its flags byte at +4 has bit 0x4 set (the build's
    /// `freeEphemeralFunction`). NULL-tolerant itself. Ported — the
    /// default is
    /// [`free_ephemeral_function`](crate::sqlite::ephemeral_fn::free_ephemeral_function).
    pub free_ephemeral_function: unsafe extern "C" fn(p4: *mut u8),
    /// Record-array sweep @ 0x08386e08: walk the (arg, destructor)
    /// record array hanging off the context, calling each live
    /// destructor whose slot the `mask` does not exempt, and clearing
    /// the slot. Ported — the default is
    /// [`vdbe_context_aux_sweep`](crate::sqlite::aux_sweep::vdbe_context_aux_sweep).
    pub context_aux_cleanup: unsafe extern "C" fn(p4: *mut u8, mask: i32),
}

/// Wired defaults: all three aux destructors are their ported twins.
pub const DEFAULT_FREE_P4_AUX_OPS: FreeP4AuxOps = FreeP4AuxOps {
    value_free,
    free_ephemeral_function,
    context_aux_cleanup: vdbe_context_aux_sweep,
};

/// The active auxiliary destructors. Host tests install recording mocks.
pub static mut FREE_P4_AUX_OPS: FreeP4AuxOps = DEFAULT_FREE_P4_AUX_OPS;

/// Reads the whole aux-ops table (volatile — the table is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// defaults away).
#[inline(always)]
pub(crate) unsafe fn free_p4_aux_ops() -> FreeP4AuxOps {
    core::ptr::read_volatile(core::ptr::addr_of!(FREE_P4_AUX_OPS))
}

/// vdbe_free_p4 — original: `FUN_082cf388` @ 0x082cf388 (148 bytes).
///
/// SQLite's `freeP4`: release the P4 payload `p4` according to its tag
/// `p4type`. See the module header for the full dispatch table; in
/// short, owned pointers (dynamic strings, KeyInfos, the -9 handoff
/// form, and the unnamed -13/-12/-11 payloads) are freed raw, borrowed
/// pointers (-10/-4/-3/-2, and everything outside -13..=0 such as
/// `P4_ADVANCE`) are left alone, and the value / function-context /
/// function-definition tags go to their specialized destructors.
///
/// A NULL `p4` returns before the tag is even examined — the entry
/// `cmp r1,#0` guards every branch, including the raw-free one.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_free_p4(p4type: i32, p4: *mut u8) {
    if p4.is_null() {
        return;
    }
    match p4type {
        // Original: six jump-table slots share the `mov r0,r1; b
        // sqlite3_free` tail.
        -13 | -12 | -11 | P4_KEYINFO_HANDOFF | P4_KEYINFO | P4_DYNAMIC => tracked_free(p4),
        -10 | -4 | -3 | -2 => {}
        P4_VALUE => (free_p4_aux_ops().value_free)(p4),
        P4_FUNCCTX => {
            let ops = free_p4_aux_ops();
            // Original: `ldr r0,[r1]` — the context's first word is
            // the FuncDef.
            (ops.free_ephemeral_function)((p4 as *mut *mut u8).read());
            (ops.context_aux_cleanup)(p4, 0);
            tracked_free(p4);
        }
        P4_FUNCDEF => (free_p4_aux_ops().free_ephemeral_function)(p4),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use crate::sqlite::vdbe::P4_ADVANCE;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the aux-ops table.
    static AUX_LOCK: Mutex<()> = Mutex::new(());

    /// Every destructor/free the code under test triggered, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        ValueFree(usize),
        Ephemeral(usize),
        AuxCleanup(usize, i32),
        RawFree(usize, usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();

    unsafe extern "C" fn recording_value_free(p4: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::ValueFree(p4 as usize));
    }

    unsafe extern "C" fn recording_ephemeral(p4: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Ephemeral(p4 as usize));
    }

    unsafe extern "C" fn recording_aux_cleanup(p4: *mut u8, mask: i32) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::AuxCleanup(p4 as usize, mask));
    }

    unsafe extern "C" fn recording_heap_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::RawFree(ptr as usize, tag));
    }

    /// Holds both locks (heap first — the order `error_msg`'s tests
    /// establish), installs the recording aux ops, and routes heap
    /// frees into the event log. The guards must stay alive for the
    /// whole test.
    fn bench() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let heap_guard = mock_heap();
        let aux_guard = AUX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(FREE_P4_AUX_OPS),
                FreeP4AuxOps {
                    value_free: recording_value_free,
                    free_ephemeral_function: recording_ephemeral,
                    context_aux_cleanup: recording_aux_cleanup,
                },
            );
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
        }
        (heap_guard, aux_guard)
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`). Raw
    /// block at offset 0 of a 32-aligned buffer, payload at raw + 32,
    /// pad word 32 - 8 = 24.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = TrackedBlock([0; 64]);
            block.0[0..4].copy_from_slice(&size.to_le_bytes());
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
    fn a_null_payload_returns_before_the_tag_is_examined() {
        let _guards = bench();
        let sentinel = 0xdead_beefusize as *mut u8;
        // A payload of NULL must not dispatch even for tags that would
        // otherwise destroy — and the raw-free branch must not reach
        // tracked_free's header walk either.
        for tag in [-13i32, -8, -7, -5, -1, 0, -14] {
            unsafe { vdbe_free_p4(tag, core::ptr::null_mut()) };
        }
        assert!(events().is_empty());
        // ... and a non-NULL payload proves the recorders were live.
        let mut block = TrackedBlock::new(24);
        unsafe { vdbe_free_p4(-2, sentinel) };
        assert!(events().is_empty(), "-2 leaves the payload alone");
        let payload = block.payload();
        unsafe { vdbe_free_p4(P4_DYNAMIC, payload) };
        assert_eq!(events().len(), 1);
    }

    #[test]
    fn owned_tags_free_the_pointer_raw_with_tag_fifty_seven() {
        let _guards = bench();
        for tag in [-13i32, -12, -11, P4_KEYINFO_HANDOFF, P4_KEYINFO, P4_DYNAMIC] {
            let mut block = TrackedBlock::new(24);
            let raw = block.raw();
            let payload = block.payload();
            unsafe { vdbe_free_p4(tag, payload) };
            assert_eq!(
                events(),
                std::vec![Event::RawFree(raw as usize, TAG_TRACKED)],
                "tag {tag} frees raw"
            );
            unsafe { (*core::ptr::addr_of_mut!(EVENTS)).clear() };
        }
    }

    #[test]
    fn borrowed_tags_leave_the_payload_untouched() {
        let _guards = bench();
        let payload = 0x1000_f000usize as *mut u8;
        for tag in [-10i32, -4, -3, -2] {
            unsafe { vdbe_free_p4(tag, payload) };
        }
        assert!(events().is_empty(), "no destructor, no free");
    }

    #[test]
    fn tags_outside_the_table_are_out_of_range() {
        let _guards = bench();
        let payload = 0x1000_f000usize as *mut u8;
        // 0 and positive tags, P4_ADVANCE (-14), and the extremes: the
        // original's `add r0,#0xd; cmp r0,#0xc` rejects all of them.
        for tag in [0i32, 1, 7, i32::MAX, P4_ADVANCE, -15, i32::MIN] {
            unsafe { vdbe_free_p4(tag, payload) };
        }
        assert!(events().is_empty());
    }

    #[test]
    fn a_value_payload_goes_to_the_value_destructor() {
        let _guards = bench();
        let payload = 0x0bad_f00dusize as *mut u8;
        unsafe { vdbe_free_p4(P4_VALUE, payload) };
        assert_eq!(events(), std::vec![Event::ValueFree(payload as usize)]);
    }

    #[test]
    fn a_funcdef_payload_goes_to_the_ephemeral_release() {
        let _guards = bench();
        let payload = 0x0bad_f00dusize as *mut u8;
        unsafe { vdbe_free_p4(P4_FUNCDEF, payload) };
        assert_eq!(events(), std::vec![Event::Ephemeral(payload as usize)]);
    }

    #[test]
    fn a_function_context_releases_its_funcdef_sweeps_aux_then_frees() {
        let _guards = bench();
        let mut block = TrackedBlock::new(24);
        let raw = block.raw();
        let payload = block.payload();
        // The context's first word is its FuncDef pointer.
        let funcdef = 0x0bad_c0deusize as *mut u8;
        unsafe { (payload as *mut *mut u8).write(funcdef) };

        unsafe { vdbe_free_p4(P4_FUNCCTX, payload) };
        assert_eq!(
            events(),
            std::vec![
                Event::Ephemeral(funcdef as usize),
                Event::AuxCleanup(payload as usize, 0),
                Event::RawFree(raw as usize, TAG_TRACKED),
            ],
            "ephemeral release, aux sweep with mask 0, raw free — in that order"
        );
    }
}
