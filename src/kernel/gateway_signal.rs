//! The RTXC kernel-gateway **signal** stub — service 2, one object id.
//!
//! Two osos addresses name the same code:
//!
//! - The literal veneer `thunk_EXT_FUN_220041cc` @ 0x08037e78. Ghidra
//!   reports 4 bytes; the true extent is **8** — the `ldr pc, [pc, #-4]`
//!   word 0xe51ff004 at 0x08037e78 plus the target word 0x220041cc at
//!   0x08037e7c, the sibling veneer to ROM 0x22001cbc opening immediately
//!   after at 0x08037e80. It is a real ADS veneer, not an empty `bx lr`
//!   destructor. Already exported as `task_lock::rom_svc_220041cc`, slot
//!   15 of the 32-thunk span catalogued in kernel/task_lock.rs.
//! - The body it jumps to, recoverable through the boot-relocator IRAM
//!   mirror: the relocator @ 0x080046e0 copies 0xaed8 bytes from
//!   0x08000000 to 0x22000000, so ROM 0x220041cc **is** osos 0x080041cc,
//!   48 bytes (0x080041cc..0x080041fc — the next stub, gateway service
//!   0x12, opens there). Absent from Ghidra's functions.csv; the extent
//!   comes from the raw words. This module ports that body.
//!
//! The mirror is genuinely executable at both addresses: its only branch
//! is the PC-relative `bl 0x08003660`, which relocates to `bl 0x22003660`
//! — the copied veneer whose absolute literal 0x0802dca8 lands back in
//! osos. So the ported body reproduces what the thunk reaches on device.
//!
//! ## The original (raw ARM @ 0x080041cc)
//!
//! ```text
//! 080041cc  str  lr, [sp, #-4]!      @ push {lr}
//! 080041d0  sub  sp, sp, #0x14       @ five-word request record
//! 080041d4  str  r0, [sp, #8]        @ word 2 = object id
//! 080041d8  mov  r0, #0
//! 080041dc  str  r0, [sp, #4]        @ word 1 = status, pre-cleared
//! 080041e0  mov  r0, #2
//! 080041e4  str  r0, [sp, #0]        @ word 0 = service selector 2
//! 080041e8  mov  r0, sp
//! 080041ec  bl   0x08003660          @ runtime::message_dispatch_veneer
//! 080041f0  ldr  r0, [sp, #4]        @ return the status word
//! 080041f4  add  sp, sp, #0x14
//! 080041f8  ldr  pc, [sp], #4
//! ```
//!
//! Words 3 and 4 of the record are never written and never read — the
//! stack frame is five words only because the ARM ADS keeps sp 8-byte
//! aligned across the `bl`. [`MaybeUninit`] preserves that without
//! materialising an invalid Rust value (the `ks_alloc_timer` idiom in
//! runtime/message_0x10.rs).
//!
//! The sibling stub for service 1 @ 0x08004368 (thunk 0x08037ea8) is the
//! same shape with word 3 additionally zeroed, and the timed variant
//! @ 0x080043c0 (thunk 0x08037ea0, ported behind `kobj::waiter_wait`)
//! writes {1, status, id, timeout, sp}: the family's record is
//! `{selector, status, args…}`, which is what fixes word 1 as the result
//! slot here.
//!
//! ## The status word is a real return value
//!
//! 20 of the 21 `bl` sites drop r0 (the next instruction always rewrites
//! it), but the 21st proves the contract. The 36-byte wrapper @
//! 0x080860c0 is:
//!
//! ```text
//! push {r4, lr}; ldr r0, [r0]; cmp r0, #0
//! moveq r0, #26; popeq {r4, pc}      @ empty slot -> error 26
//! bl 0x08037e78
//! movs r0, r0; movne r0, #0x27       @ nonzero status -> error 39
//! pop {r4, pc}
//! ```
//!
//! so zero is success and any nonzero status is an error the caller
//! translates. [`SIGNAL_OK`] records that.
//!
//! ## Call sites (binary-verified)
//!
//! Decoding every ARM B/BL word in osos.dec for every condition code
//! gives **21 `bl`** onto the veneer — 19 unconditional plus 2 `blne` —
//! and **10 tail branches** (9 `b`, 1 `beq`). No data word in osos holds
//! either 0x08037e78 or a pointer to the body, so it is never dispatched
//! virtually; the only 0x220041cc data word in the image is the veneer's
//! own literal at 0x08037e7c.
//!
//! Both predicated `bl`s are caller-side guards, not a property of this
//! stub — it has no guard of its own:
//!
//! - 0x0811f808: `ldr r0, [r0, #20]; cmn r0, #1; blne` — skip the empty
//!   slot sentinel 0xffffffff.
//! - 0x08393a1c: `ldr r0, [r1, #16]; cmp r0, #0; blne` — skip a zero id.
//!
//! Of the tail branches, 8 are fixed-id shims (`mov r0, #N; b 0x08037e78`
//! with N = 60, 28, 26, 23, 53, 52, 51, 8) plus `kobj::waiter_wake` @
//! 0x080567f8 (a bare alias, already ported) and the conditional tail
//! `beq` @ 0x080567c8 inside `csem_post` @ 0x080567a8. The `bl` sites
//! pass the same flavour of argument: a small kernel object id (18, 22,
//! 25, 28, 30, 32, 35, 36, 46, 54, 64 observed as immediates) or one
//! loaded out of an owner struct.
//!
//! ## Naming
//!
//! Selector 2 and the record layout are binary facts. The *signal*
//! reading is the repo's accumulated call-site evidence, not a decode of
//! the kernel: `csem_post` @ 0x080567a8 reaches this stub exactly when a
//! counting semaphore's count rises from -1 to 0 — i.e. when one sleeper
//! is parked — and `kobj::waiter_wake` @ 0x080567f8 is a bare alias of
//! the veneer paired with `kobj::waiter_wait`. Both are already recorded
//! that way in names.yaml. The gateway service table itself is not in
//! osos, so the RTXC primitive behind selector 2 is not proven here.
//!
//! ## Deviations
//!
//! - The dispatcher behind 0x08003660 is foreign (unported); this port
//!   calls the ported veneer [`message_dispatch_veneer`], which reaches it
//!   through the module's installable seam. Rust's call also adds the
//!   return edge the original `bl` already has, so nothing changes.
//! - match.py diffs are structural: LLVM materialises the record with its
//!   own store order and frame size rather than the ADS `sub sp, #0x14`.

use core::mem::MaybeUninit;

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// osos load address of the literal veneer that reaches this body
/// (`thunk_EXT_FUN_220041cc` @ 0x08037e78, 8 bytes).
pub const SIGNAL_THUNK: u32 = 0x0803_7e78;

/// The veneer's target word: the stub's address in relocated IRAM.
pub const SIGNAL_ROM_ENTRY: u32 = 0x2200_41cc;

/// The same body in osos, before the boot relocator copies it (48 bytes).
pub const SIGNAL_MIRROR_ENTRY: u32 = 0x0800_41cc;

/// Request word 0: the RTXC gateway service selector this stub posts.
pub const GATEWAY_SERVICE_SIGNAL: u32 = 2;

/// The status the wrapper @ 0x080860c0 treats as success (anything else
/// becomes its error 0x27).
pub const SIGNAL_OK: u32 = 0;

/// Words the original reserves (`sub sp, sp, #0x14`); only the first
/// three are ever touched.
const REQUEST_WORDS: usize = 5;

/// Request word holding the service selector.
const SERVICE_WORD: usize = 0;

/// Request word the stub pre-clears and returns: the RTXC status.
const STATUS_WORD: usize = 1;

/// Request word carrying the kernel object id.
const OBJECT_WORD: usize = 2;

/// gateway_signal_object — original: the ROM/IRAM body @ 0x220041cc,
/// mirrored in osos at 0x080041cc (48 bytes), reached through the
/// literal veneer @ 0x08037e78 (21 `bl` sites, 2 of them `blne`, plus 10
/// tail branches).
///
/// Builds the five-word gateway request `{2, 0, object, _, _}` in the
/// original's store order (object, then the cleared status, then the
/// selector), posts it through the 0x08003660 veneer, and returns the
/// status word the dispatcher wrote back. Zero is success.
///
/// No NULL or sentinel guard, faithful to the original: the two `blne`
/// call sites do that checking themselves.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_signal_object(object: u32) -> u32 {
    let mut request = [MaybeUninit::<u32>::uninit(); REQUEST_WORDS];
    let words = request.as_mut_ptr().cast::<u32>();
    words.add(OBJECT_WORD).write(object);
    words.add(STATUS_WORD).write(SIGNAL_OK);
    words.add(SERVICE_WORD).write(GATEWAY_SERVICE_SIGNAL);
    message_dispatch_veneer(words);
    words.add(STATUS_WORD).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static mut OBSERVED: Vec<[u32; 3]> = Vec::new();
    static mut STATUS_TO_WRITE: u32 = 0;

    /// Restores the dispatch seam and releases the shared lock.
    struct Recorder {
        _lock: MutexGuard<'static, ()>,
        saved: MessageDispatchVeneerOps,
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_VENEER_OPS = self.saved };
        }
    }

    unsafe extern "C" fn recording_dispatch(request: *mut u32) {
        OBSERVED.push([request.read(), request.add(1).read(), request.add(2).read()]);
        request.add(STATUS_WORD).write(STATUS_TO_WRITE);
    }

    fn install(status: u32) -> Recorder {
        let lock = DISPATCH_OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = unsafe { MESSAGE_DISPATCH_VENEER_OPS };
        unsafe {
            OBSERVED = Vec::new();
            STATUS_TO_WRITE = status;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: recording_dispatch,
            };
        }
        Recorder { _lock: lock, saved }
    }

    #[test]
    fn posts_selector_two_with_the_object_id_and_a_cleared_status() {
        let _recorder = install(0);
        unsafe {
            gateway_signal_object(0x2e);
            assert_eq!(
                OBSERVED.as_slice(),
                &[[GATEWAY_SERVICE_SIGNAL, SIGNAL_OK, 0x2e]],
                "record is {{2, 0, object}}, dispatched exactly once"
            );
        }
    }

    #[test]
    fn returns_the_status_the_dispatcher_writes_back() {
        // The wrapper @ 0x080860c0 maps any nonzero status to error 0x27,
        // so the status word must survive the reload at 0x080041f0.
        let _recorder = install(0x27);
        unsafe { assert_eq!(gateway_signal_object(22), 0x27) };
    }

    #[test]
    fn success_is_zero_when_the_dispatcher_leaves_the_slot_alone() {
        let _recorder = install(SIGNAL_OK);
        unsafe { assert_eq!(gateway_signal_object(64), SIGNAL_OK) };
    }

    #[test]
    fn every_call_builds_a_fresh_record() {
        // The original allocates the record on its own frame per call; a
        // stale status must never leak from one signal into the next.
        let _recorder = install(0);
        unsafe {
            for id in [8u32, 51, 52, 53, 60] {
                assert_eq!(gateway_signal_object(id), SIGNAL_OK);
            }
            let ids: Vec<u32> = OBSERVED.iter().map(|record| record[2]).collect();
            assert_eq!(ids.as_slice(), &[8, 51, 52, 53, 60]);
            assert!(
                OBSERVED
                    .iter()
                    .all(|record| record[0] == GATEWAY_SERVICE_SIGNAL && record[1] == SIGNAL_OK),
                "selector and cleared status are rebuilt every call"
            );
        }
    }

    #[test]
    fn passes_the_full_word_range_of_object_ids_through_untouched() {
        // Call sites pass small immediates *and* words loaded out of owner
        // structs (0x080cb714, 0x082d9650), so nothing may be masked.
        let _recorder = install(0);
        unsafe {
            for id in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff] {
                gateway_signal_object(id);
            }
            let ids: Vec<u32> = OBSERVED.iter().map(|record| record[2]).collect();
            assert_eq!(
                ids.as_slice(),
                &[0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff],
                "no guard, no masking — the two blne sites filter sentinels themselves"
            );
        }
    }

    #[test]
    fn records_the_veneer_and_body_addresses() {
        assert_eq!(SIGNAL_THUNK, 0x0803_7e78);
        assert_eq!(SIGNAL_ROM_ENTRY, 0x2200_41cc);
        // The relocator @ 0x080046e0 copies 0xaed8 bytes from osos
        // 0x08000000 to 0x22000000, so the two entries share an offset.
        const OSOS_BASE: u32 = 0x0800_0000;
        const RELOCATED_BYTES: u32 = 0xaed8;
        let offset = SIGNAL_ROM_ENTRY - crate::kernel::thunks::ROM_BASE;
        assert_eq!(SIGNAL_MIRROR_ENTRY, OSOS_BASE + offset);
        assert!(offset < RELOCATED_BYTES, "inside the relocated block");
    }

    #[test]
    fn the_thunk_table_agrees_with_this_module() {
        let entry = crate::kernel::thunks::ROM_THUNKS
            .iter()
            .find(|thunk| thunk.thunk_addr == SIGNAL_THUNK)
            .expect("the veneer is catalogued in kernel/thunks.rs");
        assert_eq!(entry.rom_target, SIGNAL_ROM_ENTRY);
        assert_eq!(entry.name, Some("signal_object"));
    }
}
