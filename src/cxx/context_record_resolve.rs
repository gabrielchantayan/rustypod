//! `context_record_resolve_leased` — original: `FUN_0837dc38` @
//! `0x0837dc38` (52 bytes).
//!
//! Raw ARM body, decoded from `osos.dec`:
//!
//! ```text
//! push {r4, r5, r6, lr}
//! mov  r6, r2               @ save out_record, flags, context
//! mov  r5, r1
//! mov  r4, r0
//! bl   0x082dd3d8           @ context_activity_enter(context)
//! mov  r2, r6               @ restore the original r0-r2 ...
//! mov  r1, r5
//! mov  r0, r4
//! bl   0x082dd05c           @ context_record_resolve(context, id, out, flags)
//! ldr  r1, [r4, #0xe0]      @ inline release half of the lease:
//! sub  r1, r1, #1           @   context->activity -= 1
//! str  r1, [r4, #0xe0]
//! pop  {r4, r5, r6, pc}
//! ```
//!
//! The next separately linked function begins at `0x0837dc6c` (`push
//! {r4, r5, r6, lr}` again), so the Ghidra 52-byte extent is exact; no
//! trailing literal pool. Decoding every ARM B/BL word in `osos.dec`
//! finds exactly 14 direct call sites, all unconditional plain `bl` (no
//! predicated forms, no tail `b`); the address occurs in no image data
//! word, so binding is static, never virtual.
//!
//! This is the leased wrapper around the context record resolver at
//! `0x082dd05c` (still retailOS-owned): it takes the context activity
//! lease via `context_activity_enter`, forwards ALL FOUR arguments to
//! the resolver, then releases the lease with an inline decrement of the
//! u32 at context+0xe0 and returns the resolver's status unchanged (r0
//! survives the decrement, which uses r1 only).
//!
//! Ghidra's C is wrong twice here: it reports the wrapper as `void` and
//! drops the fourth argument. The raw words prove both — r3 is never
//! touched by the wrapper, and `context_activity_enter` (36 bytes, uses
//! r0-r2 only) cannot clobber it, so the caller's r3 reaches the
//! resolver intact; callers such as `FUN_0837de5c` and
//! `context_child_handle_acquire` pass a fourth `flags` word and test
//! the returned status with `cmp r0, #0`.
//!
//! The release half is NOT a call: it is a bare `[ctx+0xe0] -= 1` with
//! no sweep-mark re-check (unlike the enter half) and no NULL guard —
//! the context must be live. The decrement wraps at zero exactly as the
//! ARM `sub` does.
//!
//! Deliberate deviations: the enter half calls the ported
//! `context_activity_enter` (cxx/context_activity.rs) directly on both
//! targets, matching `release.rs`; the resolver `0x082dd05c` remains
//! unported, so target builds call it at its retailOS load address and
//! host builds route only that boundary through a recording ops table.
//! The inline decrement uses volatile accesses (the field is shared
//! lease state; the enter port treats it as volatile for the same
//! reason) — observably identical on the memory system.

/// Volatile u32 activity count of the context object (shared with
/// `context_activity_enter`).
const CONTEXT_ACTIVITY: usize = 0xe0;

/// Resolver signature: the still-unported `FUN_082dd05c` @ `0x082dd05c`.
type ContextRecordResolve = unsafe extern "C" fn(*mut u8, u32, *mut *mut u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_context_record(
    context: *mut u8,
    record_id: u32,
    out_record: *mut *mut u8,
    flags: u32,
) -> u32 {
    let resolve: ContextRecordResolve = core::mem::transmute(0x082d_d05cusize);
    resolve(context, record_id, out_record, flags)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ResolveHostOps {
    resolve: ContextRecordResolve,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_resolve(
    _context: *mut u8,
    _record_id: u32,
    _out_record: *mut *mut u8,
    _flags: u32,
) -> u32 {
    11
}

#[cfg(not(target_os = "none"))]
const DEFAULT_RESOLVE_HOST_OPS: ResolveHostOps = ResolveHostOps {
    resolve: unavailable_resolve,
};

#[cfg(not(target_os = "none"))]
static mut RESOLVE_HOST_OPS: ResolveHostOps = DEFAULT_RESOLVE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resolve_context_record(
    context: *mut u8,
    record_id: u32,
    out_record: *mut *mut u8,
    flags: u32,
) -> u32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(RESOLVE_HOST_OPS));
    (ops.resolve)(context, record_id, out_record, flags)
}

/// context_record_resolve_leased — original: `FUN_0837dc38` @
/// `0x0837dc38` (52 bytes; 14 direct plain-`bl` call sites).
///
/// Acquires the context activity lease, forwards `(context, record_id,
/// out_record, flags)` unchanged to the resolver at `0x082dd05c`, then
/// releases the lease with an unconditional inline decrement of
/// context+0xe0 and returns the resolver's status. No NULL guard on
/// `context`; the lease is released on every path, success or failure.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_record_resolve_leased")]
#[inline(never)]
pub unsafe extern "C" fn context_record_resolve_leased(
    context: *mut u8,
    record_id: u32,
    out_record: *mut *mut u8,
    flags: u32,
) -> u32 {
    crate::cxx::context_activity::context_activity_enter(context);
    let status = resolve_context_record(context, record_id, out_record, flags);
    let activity = context.add(CONTEXT_ACTIVITY) as *mut u32;
    activity.write_volatile(activity.read_volatile().wrapping_sub(1));
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut LAST_CALL: Option<(*mut u8, u32, *mut *mut u8, u32)> = None;
    static mut STATUS: u32 = 0;
    static mut RECORD: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_resolve(
        context: *mut u8,
        record_id: u32,
        out_record: *mut *mut u8,
        flags: u32,
    ) -> u32 {
        LAST_CALL = Some((context, record_id, out_record, flags));
        if STATUS == 0 {
            out_record.write(RECORD);
        }
        STATUS
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    struct Bench {
        _lock: TestLock,
    }

    fn bench(status: u32, record: *mut u8) -> Bench {
        let lock = lock_ops();
        unsafe {
            LAST_CALL = None;
            STATUS = status;
            RECORD = record;
            core::ptr::addr_of_mut!(RESOLVE_HOST_OPS).write_volatile(ResolveHostOps {
                resolve: recording_resolve,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RESOLVE_HOST_OPS)
                    .write_volatile(DEFAULT_RESOLVE_HOST_OPS);
            }
        }
    }

    /// 0x100-byte context fixture filled with a sentinel, with the sweep
    /// mark at +0xdc and the activity count at +0xe0.
    #[repr(align(8))]
    struct ContextFixture {
        bytes: [u8; 0x100],
    }

    impl ContextFixture {
        fn new(marked: u32, activity: u32) -> Self {
            let mut fixture = ContextFixture { bytes: [0xa5u8; 0x100] };
            fixture.set_word(0xdc, marked);
            fixture.set_word(CONTEXT_ACTIVITY, activity);
            fixture
        }

        fn set_word(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
        }

        /// Only +0xe0 may differ from the freshly built fixture: the
        /// lease counter is the sole field this wrapper may write.
        fn assert_untouched_except_activity(&self, before: &ContextFixture) {
            for offset in (0..0x100usize).step_by(4) {
                if offset == CONTEXT_ACTIVITY {
                    continue;
                }
                assert_eq!(
                    self.word(offset),
                    before.word(offset),
                    "word at {offset:#x} must not be modified"
                );
            }
        }
    }

    #[test]
    fn success_forwards_all_four_arguments_and_returns_zero() {
        let mut fixture = ContextFixture::new(0, 7);
        let before = ContextFixture::new(0, 7);
        let mut record_storage = [0u8; 8];
        let _bench = bench(0, record_storage.as_mut_ptr());
        let mut out = core::ptr::null_mut();

        let status = unsafe {
            context_record_resolve_leased(fixture.bytes.as_mut_ptr(), 42, &mut out, 0xdead_beef)
        };

        assert_eq!(status, 0);
        assert_eq!(out, record_storage.as_mut_ptr());
        assert_eq!(
            unsafe { LAST_CALL },
            Some((fixture.bytes.as_mut_ptr(), 42, &mut out as *mut *mut u8, 0xdead_beef)),
            "context, id, out slot and the r3 flags word must arrive verbatim"
        );
        fixture.assert_untouched_except_activity(&before);
    }

    #[test]
    fn lease_is_acquired_and_released_around_the_resolver() {
        // Initial count 7: enter bumps to 8, the inline release drops it
        // back to exactly 7 — never 6 (double release) or 8 (leak).
        let mut fixture = ContextFixture::new(0, 7);
        let _bench = bench(0, core::ptr::null_mut());
        let mut out = core::ptr::null_mut();

        unsafe { context_record_resolve_leased(fixture.bytes.as_mut_ptr(), 1, &mut out, 0) };

        assert_eq!(fixture.word(CONTEXT_ACTIVITY), 7);
    }

    #[test]
    fn nonzero_status_passes_through_and_still_releases_the_lease() {
        // The original has no early-out: the decrement follows the bl
        // unconditionally, so a resolver failure leaves no leaked lease.
        for failure in [11u32, 13, 0x8000_0001] {
            let mut fixture = ContextFixture::new(0, 3);
            let _bench = bench(failure, core::ptr::null_mut());
            let mut out = core::ptr::null_mut();

            let status = unsafe {
                context_record_resolve_leased(fixture.bytes.as_mut_ptr(), 9, &mut out, 0)
            };

            assert_eq!(status, failure, "status must pass through unchanged");
            assert_eq!(fixture.word(CONTEXT_ACTIVITY), 3, "lease released on failure");
        }
    }

    #[test]
    fn marked_context_lease_nets_to_zero_change() {
        // Enter on a marked context with count 0 re-stores 1 twice; the
        // inline release must still net the count back to its initial
        // value, and the mark flag is never written by this wrapper.
        let mut fixture = ContextFixture::new(1, 0);
        let before = ContextFixture::new(1, 0);
        let _bench = bench(0, core::ptr::null_mut());
        let mut out = core::ptr::null_mut();

        unsafe { context_record_resolve_leased(fixture.bytes.as_mut_ptr(), 5, &mut out, 0) };

        assert_eq!(fixture.word(CONTEXT_ACTIVITY), 0);
        assert_eq!(fixture.word(0xdc), 1);
        fixture.assert_untouched_except_activity(&before);
    }

    #[test]
    fn release_decrement_wraps_like_the_arm_sub() {
        // Initial u32::MAX: enter wraps to 0 (skipping the marked
        // transition path), the release `sub` wraps back to u32::MAX.
        let mut fixture = ContextFixture::new(1, u32::MAX);
        let _bench = bench(0, core::ptr::null_mut());
        let mut out = core::ptr::null_mut();

        unsafe { context_record_resolve_leased(fixture.bytes.as_mut_ptr(), 2, &mut out, 0) };

        assert_eq!(fixture.word(CONTEXT_ACTIVITY), u32::MAX);
    }
}
