//! `media_player_transition_dispatch` — original: `FUN_0817dff8` @
//! `0x0817dff8`.
//!
//! Raw ARM establishes the true **132-byte** extent
//! `0x0817dff8..0x0817e07c`; `0x0817e07c` is the next function (`push
//! {r4,r5,r6,lr}`). It has two plain `bl` instructions (`0x0817ddd0`,
//! `0x081ded14`), two predicated `blne` instructions (`0x082317a4`,
//! `0x08231744`), and a tail `b 0x081df20c`.
//!
//! The dispatcher marks its state byte 3. A former zero state is initialized;
//! former 3, or a value other than 5/6, returns. It conditionally forwards two
//! nonzero transition values through the object's +0x1c/+0x20 fields, then
//! obtains the shared dispatcher and tail-dispatches it with the +0x1c word.
//!
//! # Deliberate deviations
//!
//! The five callees are unported. Target builds call their verified retailOS
//! addresses. Host builds expose the exact call boundary as replaceable seams;
//! this makes the state gate and argument routing testable without assigning
//! unverified identities to those callees.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const STATE_OFFSET: usize = 0;
const HANDLE_OFFSET: usize = 0x1c;
const TARGET_HANDLE_OFFSET: usize = 0x20;
const RETAIL_STATE_ZERO_HANDLER: usize = 0x0817_ddd0;
const RETAIL_FIRST_VALUE_FORWARD: usize = 0x0823_17a4;
const RETAIL_SECOND_VALUE_FORWARD: usize = 0x0823_1744;
const RETAIL_DISPATCHER_GET: usize = 0x081d_ed14;
const RETAIL_FOLLOWUP_DISPATCH: usize = 0x081d_f20c;

pub type StateZeroHandler = unsafe extern "C" fn(*mut u8);
pub type ValueForward = unsafe extern "C" fn(*mut u8, u32, u32);
pub type DispatcherGet = unsafe extern "C" fn() -> *mut u8;
pub type FollowupDispatch = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn state_zero_handler(object: *mut u8) {
    let call: StateZeroHandler = unsafe { core::mem::transmute(RETAIL_STATE_ZERO_HANDLER) };
    unsafe { call(object) };
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn first_value_forward(target: *mut u8, handle: u32, value: u32) {
    let call: ValueForward = unsafe { core::mem::transmute(RETAIL_FIRST_VALUE_FORWARD) };
    unsafe { call(target, handle, value) };
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn second_value_forward(target: *mut u8, handle: u32, value: u32) {
    let call: ValueForward = unsafe { core::mem::transmute(RETAIL_SECOND_VALUE_FORWARD) };
    unsafe { call(target, handle, value) };
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatcher_get() -> *mut u8 {
    let call: DispatcherGet = unsafe { core::mem::transmute(RETAIL_DISPATCHER_GET) };
    unsafe { call() }
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn followup_dispatch(dispatcher: *mut u8, handle: u32) {
    let call: FollowupDispatch = unsafe { core::mem::transmute(RETAIL_FOLLOWUP_DISPATCH) };
    unsafe { call(dispatcher, handle) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_state_zero_handler(_object: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_value_forward(_target: *mut u8, _handle: u32, _value: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatcher_get() -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_followup_dispatch(_dispatcher: *mut u8, _handle: u32) {}

/// Host seams for the five unported retailOS callees.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct MediaPlayerTransitionDispatchOps {
    pub state_zero_handler: StateZeroHandler,
    pub first_value_forward: ValueForward,
    pub second_value_forward: ValueForward,
    pub dispatcher_get: DispatcherGet,
    pub followup_dispatch: FollowupDispatch,
}
#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEDIA_PLAYER_TRANSITION_DISPATCH_OPS: MediaPlayerTransitionDispatchOps = MediaPlayerTransitionDispatchOps {
    state_zero_handler: missing_state_zero_handler,
    first_value_forward: missing_value_forward,
    second_value_forward: missing_value_forward,
    dispatcher_get: missing_dispatcher_get,
    followup_dispatch: missing_followup_dispatch,
};
#[cfg(not(target_os = "none"))]
pub static mut MEDIA_PLAYER_TRANSITION_DISPATCH_OPS: MediaPlayerTransitionDispatchOps = DEFAULT_MEDIA_PLAYER_TRANSITION_DISPATCH_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> MediaPlayerTransitionDispatchOps {
    unsafe { core::ptr::read_volatile(addr_of!(MEDIA_PLAYER_TRANSITION_DISPATCH_OPS)) }
}

/// Executes the media player's state-gated transition dispatch.
///
/// # Safety
/// `object` must cover the state byte and 32-bit words at +0x1c/+0x20. When
/// either value is nonzero, the target-handle word must name a valid 32-bit
/// pointer to a further 32-bit target word; this is the original's unguarded
/// double dereference.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_transition_dispatch(object: *mut u8, first_value: u32, second_value: u32) {
    let old_state = unsafe { object.add(STATE_OFFSET).read() };
    unsafe { object.add(STATE_OFFSET).write(3) };

    #[cfg(target_os = "none")]
    if old_state == 0 { unsafe { state_zero_handler(object) } }
    #[cfg(not(target_os = "none"))]
    if old_state == 0 { unsafe { (host_ops().state_zero_handler)(object) } }

    if old_state == 3 || (old_state != 0 && old_state != 5 && old_state != 6) { return; }

    let handle = unsafe { object.add(HANDLE_OFFSET).cast::<u32>().read_unaligned() };
    if first_value != 0 {
        let target_handle = unsafe { object.add(TARGET_HANDLE_OFFSET).cast::<u32>().read_unaligned() };
        let target = unsafe { (target_handle as usize as *mut *mut u8).read() };
        #[cfg(target_os = "none")]
        unsafe { first_value_forward(target, handle, first_value) };
        #[cfg(not(target_os = "none"))]
        unsafe { (host_ops().first_value_forward)(target, handle, first_value) };
    }
    if second_value != 0 {
        let target_handle = unsafe { object.add(TARGET_HANDLE_OFFSET).cast::<u32>().read_unaligned() };
        let target = unsafe { (target_handle as usize as *mut *mut u8).read() };
        #[cfg(target_os = "none")]
        unsafe { second_value_forward(target, handle, second_value) };
        #[cfg(not(target_os = "none"))]
        unsafe { (host_ops().second_value_forward)(target, handle, second_value) };
    }
    #[cfg(target_os = "none")]
    unsafe { followup_dispatch(dispatcher_get(), handle) };
    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = host_ops();
        (ops.followup_dispatch)((ops.dispatcher_get)(), handle);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static STATE_ZERO_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FIRST: AtomicUsize = AtomicUsize::new(0);
    static SECOND: AtomicUsize = AtomicUsize::new(0);
    static FOLLOWUP: AtomicUsize = AtomicUsize::new(0);
    static TARGET: AtomicUsize = AtomicUsize::new(0);
    static HANDLE: AtomicUsize = AtomicUsize::new(0);
    static DISPATCHER: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn state_zero(_object: *mut u8) { STATE_ZERO_CALLS.fetch_add(1, Ordering::SeqCst); }
    unsafe extern "C" fn first(target: *mut u8, handle: u32, value: u32) { TARGET.store(target as usize, Ordering::SeqCst); HANDLE.store(handle as usize, Ordering::SeqCst); FIRST.store(value as usize, Ordering::SeqCst); }
    unsafe extern "C" fn second(_target: *mut u8, _handle: u32, value: u32) { SECOND.store(value as usize, Ordering::SeqCst); }
    unsafe extern "C" fn dispatcher_get_mock() -> *mut u8 { 0x1234usize as *mut u8 }
    unsafe extern "C" fn followup(dispatcher: *mut u8, handle: u32) { DISPATCHER.store(dispatcher as usize, Ordering::SeqCst); FOLLOWUP.store(handle as usize, Ordering::SeqCst); }

    #[test]
    fn zero_and_transition_states_route_observed_values() {
        let _guard = crate::testing::MEDIA_PLAYER_TRANSITION_DISPATCH_TEST_LOCK.lock();
        STATE_ZERO_CALLS.store(0, Ordering::SeqCst);
        FIRST.store(0, Ordering::SeqCst);
        SECOND.store(0, Ordering::SeqCst);
        FOLLOWUP.store(0, Ordering::SeqCst);
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::MEDIA_PLAYER_TRANSITION_DISPATCH, 0x1000) else { crate::testing::note_missing_u32_fixture("media_player_transition_dispatch"); return; };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let object = slab.add(0x100);
            let target_slot = slab.add(0x200).cast::<*mut u8>();
            let target = slab.add(0x300);
            target_slot.write(target);
            object.add(HANDLE_OFFSET).cast::<u32>().write_unaligned(0xabcdef01);
            object.add(TARGET_HANDLE_OFFSET).cast::<u32>().write_unaligned(target_slot as usize as u32);
            MEDIA_PLAYER_TRANSITION_DISPATCH_OPS = MediaPlayerTransitionDispatchOps { state_zero_handler: state_zero, first_value_forward: first, second_value_forward: second, dispatcher_get: dispatcher_get_mock, followup_dispatch: followup };
            media_player_transition_dispatch(object, 7, 9);
            assert_eq!(object.read(), 3);
            assert_eq!(STATE_ZERO_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(FIRST.load(Ordering::SeqCst), 7);
            assert_eq!(SECOND.load(Ordering::SeqCst), 9);
            assert_eq!(TARGET.load(Ordering::SeqCst), target as usize);
            assert_eq!(HANDLE.load(Ordering::SeqCst), 0xabcdef01);
            assert_eq!(DISPATCHER.load(Ordering::SeqCst), 0x1234);
            assert_eq!(FOLLOWUP.load(Ordering::SeqCst), 0xabcdef01);
            MEDIA_PLAYER_TRANSITION_DISPATCH_OPS = DEFAULT_MEDIA_PLAYER_TRANSITION_DISPATCH_OPS;
        }
    }

    #[test]
    fn already_transitioning_or_unrecognized_state_returns_after_store() {
        let _guard = crate::testing::MEDIA_PLAYER_TRANSITION_DISPATCH_TEST_LOCK.lock();
        STATE_ZERO_CALLS.store(0, Ordering::SeqCst);
        let mut object = [0u8; TARGET_HANDLE_OFFSET + 4];
        unsafe {
            MEDIA_PLAYER_TRANSITION_DISPATCH_OPS = MediaPlayerTransitionDispatchOps { state_zero_handler: state_zero, first_value_forward: first, second_value_forward: second, dispatcher_get: dispatcher_get_mock, followup_dispatch: followup };
            object[0] = 3;
            media_player_transition_dispatch(object.as_mut_ptr(), 1, 1);
            object[0] = 4;
            media_player_transition_dispatch(object.as_mut_ptr(), 1, 1);
            assert_eq!(object[0], 3);
            assert_eq!(STATE_ZERO_CALLS.load(Ordering::SeqCst), 0);
            MEDIA_PLAYER_TRANSITION_DISPATCH_OPS = DEFAULT_MEDIA_PLAYER_TRANSITION_DISPATCH_OPS;
        }
    }
}
