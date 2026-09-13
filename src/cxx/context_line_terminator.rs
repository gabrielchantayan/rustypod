//! `context_record_line_terminator` — original: `FUN_082ddc40` @
//! **0x082ddc40** (60 bytes).
//!
//! Raw ARM starts with `push {r4,lr}` and ends at 0x082ddc78; the following
//! `push {r4,lr}` at 0x082ddc7c starts a distinct function, so Ghidra's
//! 60-byte extent is exact and has no literal pool. Decoding every ARM `B`/`BL`
//! immediate in `osos.dec` finds six plain unconditional `bl` callers
//! (0x082dd660, 0x082ddb64, 0x0837e104, 0x0837e81c, 0x0837ea38, and
//! 0x0837ebdc), no predicated `bl` callers, and one conditional tail caller
//! (`bne` from 0x082dd4c0). No image data word contains this address.
//!
//! Algorithm: when the low byte of `result` is CR, LF, or VT, store the full
//! result word at context+0x20. If the parser state byte at +0x0e and nesting
//! word at +0x48 are both zero, invoke the recovery routine at 0x082de814 with
//! the unchanged context pointer. Return `result` regardless of the branch.
//!
//! Deliberate deviation: recovery is unported. Target builds call its fixed
//! retailOS address; host builds use a volatile callback seam. Raw ARM proves
//! that r0 passes unchanged to 0x082de814, despite Ghidra dropping its argument.

#[cfg(not(target_os = "none"))]
use core::ptr;

const RETAIL_CONTEXT_RECOVER: usize = 0x082d_e814;

#[repr(C)]
struct ContextLineTerminatorFields {
    _before_parser_state: [u8; 0x0e],
    parser_state: u8,
    _before_pending_result: [u8; 0x11],
    pending_result: u32,
    _before_nesting_depth: [u8; 0x24],
    nesting_depth: u32,
}

/// Host boundary for the unported context recovery routine at 0x082de814.
#[cfg(not(target_os = "none"))]
pub struct ContextLineTerminatorOps {
    pub recover: unsafe extern "C" fn(*mut u8),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context_recover(_context: *mut u8) {}

/// Host callback seam for the unported context recovery routine. Target builds
/// call 0x082de814 directly.
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_LINE_TERMINATOR_OPS: ContextLineTerminatorOps = ContextLineTerminatorOps {
    recover: missing_context_recover,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_recover(context: *mut u8) {
    let recover: unsafe extern "C" fn(*mut u8) = core::mem::transmute(RETAIL_CONTEXT_RECOVER);
    recover(context);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn context_recover(context: *mut u8) {
    let recover = ptr::read_volatile(ptr::addr_of!(CONTEXT_LINE_TERMINATOR_OPS.recover));
    recover(context);
}

/// Records a CR, LF, or VT result for `context` and triggers recovery only at
/// the parser's outermost idle state. Other result values leave `context`
/// untouched. Returns `result` unchanged.
///
/// # Safety
/// `context` must point to a live context object containing readable fields at
/// +0x0e and +0x48 and a writable u32 field at +0x20. The original has no NULL
/// guard. The installed recovery operation must accept the same context pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_record_line_terminator")]
#[inline(never)]
pub unsafe extern "C" fn context_record_line_terminator(context: *mut u8, result: u32) -> u32 {
    let low_byte = result as u8;
    if low_byte == b'\r' || low_byte == b'\n' || low_byte == 0x0b {
        let fields = &mut *(context as *mut ContextLineTerminatorFields);
        fields.pending_result = result;
        if fields.parser_state == 0 && fields.nesting_depth == 0 {
            context_recover(context);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static RECOVERY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RECOVERY_CONTEXT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_recovery(context: *mut u8) {
        RECOVERY_CONTEXT.store(context as usize, Ordering::SeqCst);
        RECOVERY_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    struct ContextFixture {
        fields: ContextLineTerminatorFields,
    }

    impl ContextFixture {
        fn new(parser_state: u8, nesting_depth: u32, pending_result: u32) -> Self {
            ContextFixture {
                fields: ContextLineTerminatorFields {
                    _before_parser_state: [0xa5; 0x0e],
                    parser_state,
                    _before_pending_result: [0xa5; 0x11],
                    pending_result,
                    _before_nesting_depth: [0xa5; 0x24],
                    nesting_depth,
                },
            }
        }

        fn call(&mut self, result: u32) -> u32 {
            unsafe { context_record_line_terminator((&mut self.fields as *mut ContextLineTerminatorFields).cast(), result) }
        }
    }

    fn install_recording_recovery() {
        unsafe {
            CONTEXT_LINE_TERMINATOR_OPS = ContextLineTerminatorOps { recover: record_recovery };
        }
        RECOVERY_CALLS.store(0, Ordering::SeqCst);
        RECOVERY_CONTEXT.store(0, Ordering::SeqCst);
    }

    #[test]
    fn records_each_line_terminator_and_recovers_at_outermost_idle_state() {
        let _lock = TEST_LOCK.lock();
        install_recording_recovery();
        for result in [0xfeed_000d, 0xcafe_000a, 0xdead_000b] {
            let mut fixture = ContextFixture::new(0, 0, 0x1122_3344);

            assert_eq!(fixture.call(result), result);
            assert_eq!(fixture.fields.pending_result, result);
            assert_eq!(RECOVERY_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(RECOVERY_CONTEXT.load(Ordering::SeqCst), (&mut fixture.fields as *mut ContextLineTerminatorFields) as usize);
            RECOVERY_CALLS.store(0, Ordering::SeqCst);
        }
    }

    #[test]
    fn ignores_non_terminator_without_writing_or_recovering() {
        let _lock = TEST_LOCK.lock();
        install_recording_recovery();
        let mut fixture = ContextFixture::new(0, 0, 0x1122_3344);

        assert_eq!(fixture.call(0xfeed_0041), 0xfeed_0041);
        assert_eq!(fixture.fields.pending_result, 0x1122_3344);
        assert_eq!(RECOVERY_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn parser_state_gates_recovery_but_not_terminator_recording() {
        let _lock = TEST_LOCK.lock();
        install_recording_recovery();
        let mut fixture = ContextFixture::new(2, 0, 0);

        assert_eq!(fixture.call(0x44_000d), 0x44_000d);
        assert_eq!(fixture.fields.pending_result, 0x44_000d);
        assert_eq!(RECOVERY_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn nesting_depth_gates_recovery_but_not_terminator_recording() {
        let _lock = TEST_LOCK.lock();
        install_recording_recovery();
        let mut fixture = ContextFixture::new(0, 1, 0);

        assert_eq!(fixture.call(0x55_000a), 0x55_000a);
        assert_eq!(fixture.fields.pending_result, 0x55_000a);
        assert_eq!(RECOVERY_CALLS.load(Ordering::SeqCst), 0);
    }
}
