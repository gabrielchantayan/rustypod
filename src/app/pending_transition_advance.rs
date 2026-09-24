//! Advances a pending application transition.
//!
//! `pending_transition_advance` — original: `FUN_0811371c` @ `0x0811371c`
//! (136 bytes, `0x0811371c..0x0811371ca4`). Raw ARM establishes that the
//! literal pool word at `0x081137a4` follows the final tail branch; the `push`
//! at `0x081137a8` begins the next real function. Whole-image A32 decoding
//! finds two plain direct `bl` callers (`0x08112eb4`, `0x08116fa8`) and one
//! predicated direct `bl` caller (`0x084d066c`). The body has four plain direct
//! `bl` instructions (one readiness predicate, two phase advances, and a
//! finalizer), no predicated direct `bl` calls, and two tail branches.
//!
//! When the pending byte at `state+0x4cc` is clear, return zero. Otherwise,
//! select phase `0x2c` when the readiness predicate is false or the global
//! transition blocker is nonzero; successful phase advancement tail-dispatches
//! the subobject at `state+0x8d4`. When ready and unblocked, instead advance
//! phase `0x2d`; on success, finalize the state, clear its pending byte, and
//! tail-dispatch phase `0x2e`. Deliberate deviation: Rust makes the two ARM
//! tail branches ordinary calls. The direct callees have no recovered semantic
//! identities, so target builds invoke their verified retailOS addresses and
//! host builds use ABI seams.

#[cfg(target_os = "none")]
use core::mem;

const PENDING_OFFSET: usize = 0x4cc;
const TRANSITION_SUBOBJECT_OFFSET: usize = 0x8d4;
const TRANSITION_BLOCKER_ADDRESS: *const u32 = 0x089c_a670 as *const u32;

type ReadinessPredicate = unsafe extern "C" fn() -> u32;
type PhaseAdvance = unsafe extern "C" fn(*mut u8, u32) -> u32;
type StateFinalize = unsafe extern "C" fn(*mut u8);
type SubobjectAdvance = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_readiness_predicate() -> u32 {
    panic!("install pending-transition readiness seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_phase_advance(_: *mut u8, _: u32) -> u32 {
    panic!("install pending-transition phase seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_state_finalize(_: *mut u8) {
    panic!("install pending-transition finalizer seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_subobject_advance(_: *mut u8) -> u32 {
    panic!("install pending-transition subobject seam")
}

/// Host replacements for the unported direct calls and global blocker word.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct PendingTransitionAdvanceOps {
    pub readiness: ReadinessPredicate,
    pub phase_advance: PhaseAdvance,
    pub finalize: StateFinalize,
    pub subobject_advance: SubobjectAdvance,
    pub transition_blocker: u32,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_PENDING_TRANSITION_ADVANCE_OPS: PendingTransitionAdvanceOps = PendingTransitionAdvanceOps {
    readiness: missing_readiness_predicate,
    phase_advance: missing_phase_advance,
    finalize: missing_state_finalize,
    subobject_advance: missing_subobject_advance,
    transition_blocker: 0,
};

#[cfg(not(target_os = "none"))]
pub static mut PENDING_TRANSITION_ADVANCE_OPS: PendingTransitionAdvanceOps = DEFAULT_PENDING_TRANSITION_ADVANCE_OPS;

/// # Safety
///
/// `state` must name a writable retailOS application state object through
/// `+0x8d4`. Its pending-transition callees must satisfy their recovered ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_transition_advance(state: *mut u8) -> u32 {
    if state.add(PENDING_OFFSET).read_volatile() == 0 {
        return 0;
    }

    #[cfg(target_os = "none")]
    {
        let readiness: ReadinessPredicate = mem::transmute(0x081d_1f0cusize);
        let phase_advance: PhaseAdvance = mem::transmute(0x0811_49f8usize);
        let finalize: StateFinalize = mem::transmute(0x0811_1584usize);
        let subobject_advance: SubobjectAdvance = mem::transmute(0x0812_bf4cusize);
        if readiness() == 0 || TRANSITION_BLOCKER_ADDRESS.read_volatile() != 0 {
            let result = phase_advance(state, 0x2c);
            return if result == 0x2c { subobject_advance(state.add(TRANSITION_SUBOBJECT_OFFSET)) } else { result };
        }
        let result = phase_advance(state, 0x2d);
        if result != 0x2d { return result; }
        finalize(state);
        state.add(PENDING_OFFSET).write_volatile(0);
        return phase_advance(state, 0x2e);
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = PENDING_TRANSITION_ADVANCE_OPS;
        if (ops.readiness)() == 0 || ops.transition_blocker != 0 {
            let result = (ops.phase_advance)(state, 0x2c);
            return if result == 0x2c { (ops.subobject_advance)(state.add(TRANSITION_SUBOBJECT_OFFSET)) } else { result };
        }
        let result = (ops.phase_advance)(state, 0x2d);
        if result != 0x2d { return result; }
        (ops.finalize)(state);
        state.add(PENDING_OFFSET).write_volatile(0);
        (ops.phase_advance)(state, 0x2e)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut READINESS: u32 = 0;
    static mut PHASES: [u32; 2] = [0; 2];
    static mut PHASE_COUNT: usize = 0;
    static mut PHASE_RESULTS: [u32; 2] = [0; 2];
    static mut FINALIZED: bool = false;
    static mut SUBOBJECT: usize = 0;

    unsafe extern "C" fn readiness() -> u32 { READINESS }
    unsafe extern "C" fn phase_advance(_: *mut u8, phase: u32) -> u32 {
        PHASES[PHASE_COUNT] = phase;
        let result = PHASE_RESULTS[PHASE_COUNT];
        PHASE_COUNT += 1;
        result
    }
    unsafe extern "C" fn finalize(_: *mut u8) { FINALIZED = true; }
    unsafe extern "C" fn subobject_advance(subobject: *mut u8) -> u32 {
        SUBOBJECT = subobject as usize;
        0xa5
    }

    fn install(blocker: u32, ready: u32, results: [u32; 2]) {
        unsafe {
            READINESS = ready;
            PHASES = [0; 2];
            PHASE_COUNT = 0;
            PHASE_RESULTS = results;
            FINALIZED = false;
            SUBOBJECT = 0;
            PENDING_TRANSITION_ADVANCE_OPS = PendingTransitionAdvanceOps {
                readiness, phase_advance, finalize, subobject_advance, transition_blocker: blocker,
            };
        }
    }

    #[test]
    fn inactive_state_returns_zero_without_observing_seams() {
        let _guard = TEST_LOCK.lock();
        let mut state = [0u8; TRANSITION_SUBOBJECT_OFFSET + 1];
        install(0, 1, [0x2d, 0x2e]);
        assert_eq!(unsafe { pending_transition_advance(state.as_mut_ptr()) }, 0);
        unsafe { assert_eq!(PHASE_COUNT, 0); assert!(!FINALIZED); }
    }

    #[test]
    fn blocked_transition_advances_2c_and_dispatches_subobject_only_on_success() {
        let _guard = TEST_LOCK.lock();
        let mut state = [0u8; TRANSITION_SUBOBJECT_OFFSET + 1];
        state[PENDING_OFFSET] = 1;
        install(1, 1, [0x2c, 0]);
        assert_eq!(unsafe { pending_transition_advance(state.as_mut_ptr()) }, 0xa5);
        unsafe {
            assert_eq!(&PHASES[..PHASE_COUNT], &[0x2c]);
            assert_eq!(SUBOBJECT, state.as_mut_ptr().wrapping_add(TRANSITION_SUBOBJECT_OFFSET) as usize);
            assert!(!FINALIZED);
        }
    }

    #[test]
    fn ready_transition_finalizes_clears_pending_and_advances_2e() {
        let _guard = TEST_LOCK.lock();
        let mut state = [0u8; TRANSITION_SUBOBJECT_OFFSET + 1];
        state[PENDING_OFFSET] = 1;
        install(0, 1, [0x2d, 0x2e]);
        assert_eq!(unsafe { pending_transition_advance(state.as_mut_ptr()) }, 0x2e);
        unsafe { assert_eq!(&PHASES[..PHASE_COUNT], &[0x2d, 0x2e]); assert!(FINALIZED); }
        assert_eq!(state[PENDING_OFFSET], 0);
    }
}
