//! `app_transition_cleanup` — original: `FUN_082962d8` @ **0x082962d8**
//! (**132 bytes**, `0x082962d8..0x0829635c`; the next separately linked
//! function starts with `push {r4,lr}` at `0x0829635c`).
//!
//! Whole-image ARM B/BL-immediate decoding finds **3 incoming plain `bl` call
//! sites** and **0 predicated `bl` forms**. The body has 12 unconditional
//! direct `bl` instructions and tail-branches to `lazy_handle_manager_release`.
//!
//! Algorithm: select a fall-through cleanup suffix from the state word at
//! `+0x25c`; all selections perform the common finalizers, then release the
//! handle at `+0x2b4` through the shared lazy-handle manager. The identities of
//! the unported cleanup calls are not recovered; target builds call their
//! verified retail addresses and host tests inject them. Deliberate deviations:
//! the stock tail branch is a normal Rust call so the port has a safe ABI.

#[cfg(target_os = "none")]
use crate::app::lazy_handle_manager::lazy_handle_manager_get;
use crate::app::lazy_handle_manager::LazyHandleManager;
#[cfg(target_os = "none")]
use crate::app::lazy_handle_manager_release::lazy_handle_manager_release;

const STATE_OFFSET: usize = 0x25c;
const PHASE_ONE_ARGUMENT_OFFSET: usize = 0x298;
const PHASE_FIVE_ARGUMENT_OFFSET: usize = 0x294;
const HANDLE_OFFSET: usize = 0x2b4;

type StateCall = unsafe extern "C" fn(*mut u8);
type WordCall = unsafe extern "C" fn(u32);
type VoidCall = unsafe extern "C" fn();
type ManagerGet = unsafe extern "C" fn() -> *mut LazyHandleManager;
type ManagerRelease = unsafe extern "C" fn(*mut LazyHandleManager, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn call_retail_state(address: usize, state: *mut u8) {
    let call: StateCall = core::mem::transmute(address);
    call(state);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn call_retail_word(address: usize, word: u32) {
    let call: WordCall = core::mem::transmute(address);
    call(word);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn call_retail_void(address: usize) {
    let call: VoidCall = core::mem::transmute(address);
    call();
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_state(_: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_word(_: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_void() {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_manager_get() -> *mut LazyHandleManager { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_manager_release(_: *mut LazyHandleManager, _: u32) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct AppTransitionCleanupOps {
    pub phase_zero: StateCall,
    pub phase_five_void: VoidCall,
    pub phase_one: WordCall,
    pub phase_two: VoidCall,
    pub phase_three: VoidCall,
    pub phase_four: VoidCall,
    pub phase_five: WordCall,
    pub phase_six: VoidCall,
    pub phase_seven: VoidCall,
    pub common_one: VoidCall,
    pub common_two: StateCall,
    pub manager_get: ManagerGet,
    pub manager_release: ManagerRelease,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_APP_TRANSITION_CLEANUP_OPS: AppTransitionCleanupOps = AppTransitionCleanupOps {
    phase_zero: no_op_state,
    phase_one: no_op_word,
    phase_two: no_op_void,
    phase_five_void: no_op_void,
    phase_three: no_op_void,
    phase_four: no_op_void,
    phase_five: no_op_word,
    phase_six: no_op_void,
    phase_seven: no_op_void,
    common_one: no_op_void,
    common_two: no_op_state,
    manager_get: no_op_manager_get,
    manager_release: no_op_manager_release,
};

#[cfg(not(target_os = "none"))]
pub static mut APP_TRANSITION_CLEANUP_OPS: AppTransitionCleanupOps = DEFAULT_APP_TRANSITION_CLEANUP_OPS;

/// Runs the state-selected cleanup suffix and releases the state's lazy handle.
///
/// # Safety
///
/// `state` must point to the retail object layout, including aligned words at
/// `+0x25c`, `+0x294`, `+0x298`, and `+0x2b4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_transition_cleanup(state: *mut u8) {
    let cleanup_state = (state.add(STATE_OFFSET) as *const u32).read_volatile();

    #[cfg(target_os = "none")]
    if cleanup_state <= 6 {
        if cleanup_state == 0 {
            call_retail_state(0x0829_5fdc, state);
        }
        if cleanup_state <= 1 {
            call_retail_word(0x081e_e378, (state.add(PHASE_ONE_ARGUMENT_OFFSET) as *const u32).read_volatile());
        }
        if cleanup_state <= 2 {
            call_retail_void(0x0818_9464);
            call_retail_void(0x0818_9d10);
        }
        if cleanup_state <= 3 {
            call_retail_void(0x0807_6b5c);
        }
        if cleanup_state <= 4 {
            call_retail_void(0x080c_00f0);
        }
        if cleanup_state <= 5 {
            call_retail_word(0x081b_c3c0, (state.add(PHASE_FIVE_ARGUMENT_OFFSET) as *const u32).read_volatile());
        }
        call_retail_void(0x081b_bde8);
        call_retail_void(0x081b_beec);
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = APP_TRANSITION_CLEANUP_OPS;
        if cleanup_state <= 6 {
            if cleanup_state == 0 {
                (ops.phase_zero)(state);
            }
            if cleanup_state <= 1 {
                (ops.phase_one)((state.add(PHASE_ONE_ARGUMENT_OFFSET) as *const u32).read_volatile());
            }
            if cleanup_state <= 2 {
                (ops.phase_two)();
                (ops.phase_three)();
            }
            if cleanup_state <= 3 {
                (ops.phase_four)();
            }
            if cleanup_state <= 4 {
                (ops.phase_five_void)();
            }
            if cleanup_state <= 5 {
                (ops.phase_five)((state.add(PHASE_FIVE_ARGUMENT_OFFSET) as *const u32).read_volatile());
            }
            (ops.phase_six)();
            (ops.phase_seven)();
        }
        (ops.common_one)();
        (ops.common_two)(state);
        (ops.manager_release)((ops.manager_get)(), (state.add(HANDLE_OFFSET) as *const u32).read_volatile());
        return;
    }

    #[cfg(target_os = "none")]
    {
        call_retail_void(0x0810_60dc);
        call_retail_state(0x0829_6504, state);
        lazy_handle_manager_release(lazy_handle_manager_get(), (state.add(HANDLE_OFFSET) as *const u32).read_volatile());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 16] = [0; 16];
    static mut EVENT_COUNT: usize = 0;
    static mut WORDS: [u32; 2] = [0; 2];

    unsafe fn event(value: u8) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn state_call(_: *mut u8) { event(0); }
    unsafe extern "C" fn word_one(value: u32) { WORDS[0] = value; event(1); }
    unsafe extern "C" fn phase_two() { event(2); }
    unsafe extern "C" fn phase_three() { event(3); }
    unsafe extern "C" fn phase_four() { event(4); }
    unsafe extern "C" fn phase_five_void() { event(5); }
    unsafe extern "C" fn word_five(value: u32) { WORDS[1] = value; event(6); }
    unsafe extern "C" fn phase_six() { event(7); }
    unsafe extern "C" fn phase_seven() { event(8); }
    unsafe extern "C" fn common_one() { event(9); }
    unsafe extern "C" fn common_two(_: *mut u8) { event(10); }
    unsafe extern "C" fn manager_get() -> *mut LazyHandleManager { event(11); core::ptr::null_mut() }
    unsafe extern "C" fn manager_release(_: *mut LazyHandleManager, value: u32) { WORDS[0] = value; event(12); }

    fn ops() -> AppTransitionCleanupOps { AppTransitionCleanupOps { phase_zero: state_call, phase_one: word_one, phase_two, phase_three, phase_four, phase_five_void, phase_five: word_five, phase_six, phase_seven, common_one, common_two, manager_get, manager_release } }

    #[repr(align(4))]
    struct State([u8; 0x2b8]);

    #[test]
    fn transition_cleanup_runs_each_fallthrough_suffix_and_common_tail() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            APP_TRANSITION_CLEANUP_OPS = ops();
            for (phase, expected) in [(0, 13usize), (1, 12), (2, 11), (3, 9), (4, 8), (5, 7), (6, 6), (7, 4), (u32::MAX, 4)] {
                let mut state = State([0; 0x2b8]);
                (state.0.as_mut_ptr().add(STATE_OFFSET) as *mut u32).write(phase);
                (state.0.as_mut_ptr().add(PHASE_ONE_ARGUMENT_OFFSET) as *mut u32).write(0x1122_3344);
                (state.0.as_mut_ptr().add(PHASE_FIVE_ARGUMENT_OFFSET) as *mut u32).write(0x5566_7788);
                (state.0.as_mut_ptr().add(HANDLE_OFFSET) as *mut u32).write(0xaabb_ccdd);
                EVENT_COUNT = 0; WORDS = [0; 2];
                app_transition_cleanup(state.0.as_mut_ptr());
                assert_eq!(EVENT_COUNT, expected, "phase {phase}");
                assert_eq!(EVENTS[EVENT_COUNT - 4..EVENT_COUNT], [9, 10, 11, 12]);
                assert_eq!(WORDS[0], 0xaabb_ccdd);
                if phase == 0 { assert_eq!(&EVENTS[..13], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); assert_eq!(WORDS[1], 0x5566_7788); }
                if phase == 2 { assert_eq!(&EVENTS[..11], &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); assert_eq!(WORDS[1], 0x5566_7788); }
            }
            APP_TRANSITION_CLEANUP_OPS = DEFAULT_APP_TRANSITION_CLEANUP_OPS;
        }
    }
}
