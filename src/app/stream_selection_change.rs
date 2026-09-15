//! `stream_selection_change` — original: `FUN_081cbbf4` @ `0x081cbbf4`
//! (**104 bytes**, `0x081cbbf4..0x081cbc5c`).
//!
//! Raw ARM first compares the requested selection against `state+0x8c4` and
//! returns unchanged on equality. Otherwise it stores the selection, refreshes
//! the embedded mode-selected stream at `state+0x1c`, caches its extent minus
//! one at `state+0x8c0`, clears the cached position at `state+0x8b8` to -1,
//! clamps the active position, then tail-dispatches message `(0x848a,
//! 0x53747220)` through vtable slot `+0x58`.
//!
//! The true body has four unconditional direct `bl` instructions at
//! `0x081cbc10`, `0x081cbc20`, `0x081cbc34`, and `0x081cbc44`; it has zero
//! predicated `bl` instructions. The final vtable dispatch is `ldr pc,[r0,#0x58]`,
//! not a `bl`. The next separately linked function begins at `0x081cbc5c`.
//!
//! Deliberate deviations: none. The unported refresh callee and virtual message
//! target are fixed-address/direct-slot calls on ARM and replaceable host seams.
use super::mode_selected_extent::mode_selected_extent;
use super::mode_selected_position::mode_selected_position;
use super::clamped_mode_position::set_clamped_mode_position;

const BACKEND_OFFSET: usize = 0x1c;
const CACHED_POSITION_OFFSET: usize = 0x8b8;
const CACHED_EXTENT_MINUS_ONE_OFFSET: usize = 0x8c0;
const SELECTION_OFFSET: usize = 0x8c4;
const MESSAGE_CATEGORY: u32 = 0x848a;
const MESSAGE_NAME: u32 = 0x5374_7220;

pub type RefreshModeSelectedStream = unsafe extern "C" fn(*mut u8, u32, u32, u32);
pub type StateMessageDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_refresh_mode_selected_stream(_: *mut u8, _: u32, _: u32, _: u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_state_message_dispatch(_: *mut u8, _: u32, _: u32) {}

/// Host replacement for the unported refresh at `0x0822ab84`.
#[cfg(not(target_arch = "arm"))]
pub static mut REFRESH_MODE_SELECTED_STREAM: RefreshModeSelectedStream = missing_refresh_mode_selected_stream;
/// Host replacement for the state vtable's `+0x58` message-dispatch slot.
#[cfg(not(target_arch = "arm"))]
pub static mut STATE_MESSAGE_DISPATCH: StateMessageDispatch = missing_state_message_dispatch;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn refresh_mode_selected_stream(state: *mut u8, selection: u32, arg2: u32, arg3: u32) {
    let refresh: RefreshModeSelectedStream = core::mem::transmute(0x0822_ab84usize);
    refresh(state.add(BACKEND_OFFSET), selection, arg2, arg3);
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn refresh_mode_selected_stream(state: *mut u8, selection: u32, arg2: u32, arg3: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(REFRESH_MODE_SELECTED_STREAM))(
        state.add(BACKEND_OFFSET), selection, arg2, arg3,
    );
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn dispatch_state_message(state: *mut u8) {
    let vtable = state.cast::<*const u32>().read();
    let dispatch: StateMessageDispatch = core::mem::transmute(vtable.add(0x58 / 4).read() as usize);
    dispatch(state, MESSAGE_CATEGORY, MESSAGE_NAME);
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn dispatch_state_message(state: *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(STATE_MESSAGE_DISPATCH))(
        state, MESSAGE_CATEGORY, MESSAGE_NAME,
    );
}

/// Changes the selected stream and synchronizes its cached bounds and position.
///
/// # Safety
/// `state` must be non-NULL and four-byte aligned, with readable/writable words
/// at `+0x8b8`, `+0x8c0`, and `+0x8c4`, and a valid embedded backend at `+0x1c`.
/// The target build also requires a vtable pointer at `state+0` whose `+0x58`
/// slot accepts `(state, u32, u32)`; retailOS performs no guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_selection_change(state: *mut u8, selection: u32, arg2: u32, arg3: u32) {
    if state.add(SELECTION_OFFSET).cast::<u32>().read() == selection {
        return;
    }
    state.add(SELECTION_OFFSET).cast::<u32>().write(selection);
    refresh_mode_selected_stream(state, selection, arg2, arg3);
    let backend = state.add(BACKEND_OFFSET);
    state.add(CACHED_EXTENT_MINUS_ONE_OFFSET).cast::<u32>().write(mode_selected_extent(backend).wrapping_sub(1));
    state.add(CACHED_POSITION_OFFSET).cast::<u32>().write(u32::MAX);
    set_clamped_mode_position(state, mode_selected_position(backend));
    dispatch_state_message(state);
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE_BYTES: usize = SELECTION_OFFSET + 4;
    #[repr(align(4))]
    struct State([u8; STATE_BYTES]);
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut REFRESH_CALLS: u32 = 0;
    static mut REFRESH_ARGS: (*mut u8, u32, u32, u32) = (core::ptr::null_mut(), 0, 0, 0);
    static mut DISPATCH_ARGS: (*mut u8, u32, u32) = (core::ptr::null_mut(), 0, 0);

    unsafe extern "C" fn record_refresh(state: *mut u8, selection: u32, arg2: u32, arg3: u32) {
        REFRESH_CALLS += 1;
        REFRESH_ARGS = (state, selection, arg2, arg3);
    }
    unsafe extern "C" fn record_dispatch(state: *mut u8, category: u32, name: u32) {
        DISPATCH_ARGS = (state, category, name);
    }
    unsafe fn word(state: &mut State, offset: usize) -> *mut u32 { state.0.as_mut_ptr().add(offset).cast() }

    #[test]
    fn equal_selection_returns_without_side_effects() {
        let _lock = TEST_LOCK.lock();
        let mut state = State([0xa5; STATE_BYTES]);
        let before;
        unsafe {
            word(&mut state, SELECTION_OFFSET).write(7);
            REFRESH_CALLS = 0;
            STATE_MESSAGE_DISPATCH = record_dispatch;
            before = state.0;
            stream_selection_change(state.0.as_mut_ptr(), 7, 2, 3);
        }
        assert_eq!(unsafe { REFRESH_CALLS }, 0);
        assert_eq!(state.0, before);
    }

    #[test]
    fn changed_selection_refreshes_caches_clamps_and_dispatches() {
        let _lock = TEST_LOCK.lock();
        let mut state = State([0; STATE_BYTES]);
        unsafe {
            word(&mut state, BACKEND_OFFSET + 0x5e4).write(4);
            word(&mut state, BACKEND_OFFSET + 0x5e8).write(9);
            state.0[BACKEND_OFFSET + 0x5f8] = 0;
            word(&mut state, 0x8bc).write(0);
            word(&mut state, 0x8c0).write(10);
            REFRESH_CALLS = 0;
            REFRESH_MODE_SELECTED_STREAM = record_refresh;
            STATE_MESSAGE_DISPATCH = record_dispatch;
            stream_selection_change(state.0.as_mut_ptr(), 0x1234_5678, 0x22, 0x33);
        }
        unsafe {
            assert_eq!(REFRESH_CALLS, 1);
            assert_eq!(REFRESH_ARGS, (state.0.as_mut_ptr().add(BACKEND_OFFSET), 0x1234_5678, 0x22, 0x33));
            assert_eq!(word(&mut state, SELECTION_OFFSET).read(), 0x1234_5678);
            assert_eq!(word(&mut state, CACHED_EXTENT_MINUS_ONE_OFFSET).read(), 8);
            assert_eq!(word(&mut state, CACHED_POSITION_OFFSET).read(), 4);
            assert_eq!(DISPATCH_ARGS, (state.0.as_mut_ptr(), MESSAGE_CATEGORY, MESSAGE_NAME));
        }
    }
}
