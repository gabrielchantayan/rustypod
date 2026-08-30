//! Message-dispatch veneer — `FUN_08003660` @ 0x08003660 (8 bytes; Ghidra
//! reports 4, dropping the literal-pool word).
//!
//! ```text
//! 08003660  ldr pc, [pc, #-4]      @ tail-branch through the literal below
//! 08003664  .word 0x0802dca8       @ the RTXC service-dispatch entry
//! ```
//!
//! The true extent is 8 bytes: the next veneer (`ldr pc, [pc, #-4]` →
//! 0x08386e64) opens at 0x08003668. This is a genuine literal veneer
//! (`0xe51ff004` + target word), not an empty `bx lr` destructor and not a
//! plain `b`.
//!
//! ## Call sites (binary-verified)
//!
//! Decoding every ARM B/BL word in osos.dec (load base 0x08000000) gives
//! **37** call sites — 36 plain `bl` plus one `blne` @ 0x08003e38 — and zero
//! plain `b` or data-word references: the veneer is never tail-branched to
//! from osos code and never dispatched virtually. The lone predicated site
//! is a caller-side guard, not a property of the veneer: 0x08003e20 checks
//! its own incoming r0 and dispatches selector 0x11 only when it is nonzero
//! (`cmp r0, #0; …; addne r0, sp, #4; blne 0x08003660`). The veneer itself
//! has no NULL guard; callers gate.
//!
//! Every caller follows one shape: build a request record on its own stack
//! with a small RTXC selector in word 0 (observed 0x0e, 0x0f, 0x10, 0x11,
//! 0x12, 0x15, 0x16, 0x17, 0x18, 0x1c, 0x1d, 0x1e…), pass `r0 = &record`,
//! then reload result words out of the record. All 37 sites discard the
//! dispatcher's r0 (the instruction after the `bl` is always an `ldr r0,
//! [sp, #N]` reload or a stack-pop), so the observable ABI is a void call
//! taking one writable record pointer.
//!
//! ## The target
//!
//! 0x0802dca8 is unported. It decodes as `add r1, sp, #0x30; mov r0, r5;
//! bl 0x0802b56c; b 0x0802dd04` — one entry in the multi-entry RTXC
//! service-stub family spanning 0x0802d9c4..0x0802ddb0, which Ghidra lumps
//! into `FUN_0802d9c4` (788 bytes) / `FUN_0802dcd8` (176 bytes). The family
//! shares tail code at 0x0802dc74/0x0802dd04/0x0802dd48, and nine sibling
//! veneers (0x08003428..0x080034a0) jump to neighbouring entries
//! 0x0802dcfc..0x0802dda0. Every entry reads its arguments from the caller's
//! stack frame and moves the firmware-wide reserved context register r5 into
//! r0: no call site writes r5 anywhere near its `bl` (verified across all
//! 37), so r5 is a fixed kernel convention (the current-task context), not
//! a per-call input. The veneer touches nothing — it is a pure tail branch,
//! so r0..r3 and the caller's sp reach the dispatcher exactly as the caller
//! left them, and the dispatcher returns directly to the caller.
//!
//! Reference: `decomp/c/000/08003660_FUN_08003660.c` (Ghidra models it as
//! `(*DAT_08003664)()`, "Treating indirect jump as call"); raw ARM above.
//!
//! ## Deviations
//!
//! - The target is foreign (unported), so the port reaches it through an
//!   installable, volatile dispatch seam — the house foreign-service
//!   boundary pattern (`heap::rom_task_start`, `runtime::message_0x17`).
//!   The target default transmutes the retail literal 0x0802dca8; host tests
//!   install a recording dispatcher.
//! - Rust expresses the tail branch as a call, adding a return edge the
//!   original lacks. Behaviour is identical for every observed caller: the
//!   record pointer flows verbatim and all 37 callers ignore r0.

/// The fixed instruction word of the veneer at 0x08003660.
pub const MESSAGE_DISPATCH_VENEER_INSN: u32 = 0xe51f_f004;

/// The literal target word at 0x08003664: the RTXC service-dispatch entry.
pub const MESSAGE_DISPATCH_TARGET: usize = 0x0802_dca8;

/// ABI of the RTXC service dispatcher behind the veneer: one writable,
/// caller-owned stack record whose layout the selector in word 0 defines.
pub type MessageDispatchVeneerFn = unsafe extern "C" fn(request: *mut u32);

/// Runtime seam for the unported dispatcher behind the veneer.
#[derive(Clone, Copy)]
pub struct MessageDispatchVeneerOps {
    pub dispatch: MessageDispatchVeneerFn,
}

unsafe extern "C" fn rom_service_dispatch(request: *mut u32) {
    let dispatch: MessageDispatchVeneerFn = core::mem::transmute(MESSAGE_DISPATCH_TARGET);
    dispatch(request);
}

/// Direct-ROM default; host tests install a recording dispatcher.
pub static mut MESSAGE_DISPATCH_VENEER_OPS: MessageDispatchVeneerOps =
    MessageDispatchVeneerOps {
        dispatch: rom_service_dispatch,
    };

/// Volatile slot read preserves the installable target seam in target code.
#[inline(always)]
unsafe fn message_dispatch_veneer_ops() -> MessageDispatchVeneerOps {
    core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_DISPATCH_VENEER_OPS))
}

/// message_dispatch_veneer — original: `FUN_08003660` @ 0x08003660 (8 bytes;
/// 37 `bl` call sites, one of them predicated `blne`).
///
/// Pure tail branch into the RTXC service dispatcher: `request` (r0) reaches
/// the dispatcher exactly as passed, and the dispatcher may rewrite the
/// caller-owned record in place — that in-place mutation is the only result
/// channel any caller observes.
///
/// Kept as its own `#[inline(never)]` symbol so a hook at 0x08003660 lands
/// on a real veneer that dispatches on to the service entry, exactly as the
/// image has it.
///
/// # Safety
///
/// `request` must point at a writable stack record whose extent matches the
/// selector in its first word; the dispatcher interprets and mutates it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn message_dispatch_veneer(request: *mut u32) {
    (message_dispatch_veneer_ops().dispatch)(request);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_COUNT: u32 = 0;
    static mut OBSERVED_REQUEST: *mut u32 = core::ptr::null_mut();

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved: MessageDispatchVeneerOps,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_VENEER_OPS = self.saved };
        }
    }

    unsafe extern "C" fn recording_dispatch(request: *mut u32) {
        CALL_COUNT += 1;
        OBSERVED_REQUEST = request;
        // The dispatcher's only observed result channel: mutate the
        // caller-owned record in place (word 1 is the status/result slot in
        // every observed wrapper).
        request.add(1).write(0x5a5a_a5a5);
    }

    fn install_recorder() -> TestOps {
        let lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let saved = unsafe { MESSAGE_DISPATCH_VENEER_OPS };
        unsafe {
            CALL_COUNT = 0;
            OBSERVED_REQUEST = core::ptr::null_mut();
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: recording_dispatch,
            };
        }
        TestOps { _lock: lock, saved }
    }

    #[test]
    fn forwards_the_request_pointer_verbatim_and_dispatches_once() {
        let _ops = install_recorder();
        let mut record = [0x17u32, 0, 0, 0];
        unsafe {
            message_dispatch_veneer(record.as_mut_ptr());
            assert_eq!(CALL_COUNT, 1, "exactly one dispatch per veneer call");
            assert_eq!(
                OBSERVED_REQUEST,
                record.as_mut_ptr(),
                "r0 flows to the dispatcher untouched"
            );
        }
    }

    #[test]
    fn dispatcher_record_mutation_is_visible_to_the_caller() {
        let _ops = install_recorder();
        let mut record = [0x10u32, 0xffff_ffff, 3, 4];
        unsafe {
            message_dispatch_veneer(record.as_mut_ptr());
            assert_eq!(
                record,
                [0x10, 0x5a5a_a5a5, 3, 4],
                "the in-place record write is the result channel; other words untouched"
            );
        }
    }

    #[test]
    fn veneer_is_a_real_distinct_symbol() {
        // A hook at 0x08003660 must land on a real branch target, not an
        // inlined-away alias of the seam.
        assert_ne!(
            message_dispatch_veneer as *const (),
            recording_dispatch as *const ()
        );
    }

    #[test]
    fn records_the_fixed_veneer_encoding() {
        assert_eq!(MESSAGE_DISPATCH_VENEER_INSN, 0xe51f_f004, "ldr pc, [pc, #-4]");
        assert_eq!(MESSAGE_DISPATCH_TARGET, 0x0802_dca8);
        assert_eq!(MESSAGE_DISPATCH_TARGET & 3, 0, "word-aligned ARM entry");
    }
}
