//! Deferred display nibble configuration.
//!
//! [`configure_display_pending_nibbles`] — original: `FUN_0828d6cc` @
//! **0x0828d6cc**. Raw `osos.dec` establishes its true **168-byte** extent:
//! 160 instruction bytes through the tail `b 0x081d8d0c`, followed by the
//! two-word literal pool at `0x0828d76c..0x0828d774`; the separately linked
//! sibling opens at `0x0828d774`. Decoding every ARM `B`/`BL` immediate in
//! the image finds **7 direct callers**, all unconditional `bl` (none
//! predicated and no tail branches): `0x0817ae2c`, `0x0817f36c`,
//! `0x0828ccc4`, `0x0828d664`, `0x0828d688`, `0x0828d6a4`, and `0x0828d6c4`.
//!
//! # Algorithm
//!
//! The routine accepts a selector in `-1..=1` and four nibble values in
//! `-1..=15`; any other value rejects the whole request before touching state
//! or calling the display. A null display becomes the secondary display.
//! Selector `-1` and nibble `-1` retain their respective global bytes;
//! nonnegative inputs update them. It then forwards the retained selector and
//! four bytes to `FUN_081d8d0c`, whose verified body writes the selector at
//! `display + 0x56`, masks each byte to four bits into `+0x57..+0x5a`, and
//! sets `display + 0x24` pending.
//!
//! # Deliberate deviations
//!
//! The global bytes at `0x089cc8a0` / `0x089cc8b8` are runtime RW state, so
//! this port models them with crate statics. `FUN_081d8d0c` is absent from
//! `names.yaml`; target builds call its verified address through a volatile
//! seam, while host tests install a recorder. No broader identity is inferred
//! for those five retained bytes.

use core::ptr;

#[cfg(test)]
extern crate std;

use crate::drivers::display::{display_get, Display, SECONDARY_DISPLAY_ID};

/// ABI of the unported `FUN_081d8d0c`, which commits one selector and four
/// masked nibbles into a display's pending state.
pub type DisplaySetPendingNibbles = unsafe extern "C" fn(*mut Display, u8, *const u8);

/// Original three-byte state block at `0x089cc8a0`. The pending-nibble
/// selector is byte 0; `apply_display_transition` owns bytes 1 and 2.
#[repr(C)]
struct DisplayPendingState {
    selector: u8,
    transition_secondary: u8,
    transition_primary: u8,
}

static mut DISPLAY_PENDING_STATE: DisplayPendingState = DisplayPendingState {
    selector: 0,
    transition_secondary: 0,
    transition_primary: 0,
};
/// Original four-byte global block at `0x089cc8b8`; a `-1` input retains its
/// corresponding byte.
static mut DISPLAY_PENDING_NIBBLES: [u8; 4] = [0; 4];

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_display_set_pending_nibbles(
    display: *mut Display,
    selector: u8,
    nibbles: *const u8,
) {
    let set: DisplaySetPendingNibbles = core::mem::transmute(0x081d_8d0cusize);
    set(display, selector, nibbles);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_display_set_pending_nibbles(
    _display: *mut Display,
    _selector: u8,
    _nibbles: *const u8,
) {
}

/// The retained `FUN_081d8d0c` boundary. Volatile loading prevents LLVM from
/// replacing the device call with a known builtin or folding away host seams.
#[cfg(target_os = "none")]
pub(crate) static mut DISPLAY_SET_PENDING_NIBBLES: DisplaySetPendingNibbles = firmware_display_set_pending_nibbles;
#[cfg(not(target_os = "none"))]
pub(crate) static mut DISPLAY_SET_PENDING_NIBBLES: DisplaySetPendingNibbles = missing_display_set_pending_nibbles;

#[cfg(test)]
pub(crate) static DISPLAY_PENDING_NIBBLES_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[inline(always)]
pub(crate) unsafe fn set_display_pending_nibbles(display: *mut Display, selector: u8, nibbles: *const u8) {
    let set = ptr::read_volatile(ptr::addr_of!(DISPLAY_SET_PENDING_NIBBLES));
    set(display, selector, nibbles);
}

/// configure_display_pending_nibbles — original: `FUN_0828d6cc` @
/// `0x0828d6cc` (168 bytes: 160 instruction bytes plus the two-word literal
/// pool; next function `0x0828d774`). **7 direct unconditional `bl` call
/// sites, no predicated calls or tail branches**, verified by decoding every
/// ARM `B`/`BL` immediate in `osos.dec`.
///
/// Atomically validates a partial selector/four-nibble update, retains each
/// `-1` field, defaults a null display to `display_get(1)`, then gives the
/// retained five-byte state to `FUN_081d8d0c`. The selector has only values
/// `-1`, `0`, and `1`; every nibble has only `-1..=15`. Invalid input returns
/// before changing the globals or invoking the display callee.
///
/// # Safety
///
/// `display` must be a live [`Display`] when non-null. The target callee has
/// no further pointer guard, exactly like the ARM path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn configure_display_pending_nibbles(
    mut display: *mut Display,
    selector: i32,
    first: i32,
    second: i32,
    third: i32,
    fourth: i32,
) {
    if !(-1..=1).contains(&selector)
        || !(-1..=15).contains(&first)
        || !(-1..=15).contains(&second)
        || !(-1..=15).contains(&third)
        || !(-1..=15).contains(&fourth)
    {
        return;
    }

    if display.is_null() {
        display = display_get(SECONDARY_DISPLAY_ID as u32);
    }

    if selector >= 0 {
        ptr::write_volatile(ptr::addr_of_mut!(DISPLAY_PENDING_STATE.selector), selector as u8);
    }

    let updates = [first, second, third, fourth];
    for (index, value) in updates.iter().enumerate() {
        if *value >= 0 {
            ptr::write_volatile(
                ptr::addr_of_mut!(DISPLAY_PENDING_NIBBLES).cast::<u8>().add(index),
                *value as u8,
            );
        }
    }

    let retained_selector = ptr::read_volatile(ptr::addr_of!(DISPLAY_PENDING_STATE.selector));
    let retained_nibbles = ptr::addr_of!(DISPLAY_PENDING_NIBBLES).cast::<u8>();
    set_display_pending_nibbles(display, retained_selector, retained_nibbles);
}

/// ABI shared by the three unported display routines reached from
/// `apply_display_transition`. Their broader identities are deliberately not
/// inferred; each verified address takes a display and one word and returns a
/// retailOS status.
type DisplayTransitionCallee = unsafe extern "C" fn(*mut Display, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_transition_first(display: *mut Display, value: u32) -> u32 {
    let callee: DisplayTransitionCallee = core::mem::transmute(0x081d_8ae8usize);
    callee(display, value)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_transition_second(display: *mut Display, value: u32) -> u32 {
    let callee: DisplayTransitionCallee = core::mem::transmute(0x081d_8db8usize);
    callee(display, value)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_transition_finish(display: *mut Display, value: u32) -> u32 {
    let callee: DisplayTransitionCallee = core::mem::transmute(0x081d_8ed0usize);
    callee(display, value)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_display_transition_callee(_display: *mut Display, _value: u32) -> u32 {
    0
}

#[cfg(target_os = "none")]
static mut DISPLAY_TRANSITION_FIRST: DisplayTransitionCallee = firmware_transition_first;
#[cfg(target_os = "none")]
static mut DISPLAY_TRANSITION_SECOND: DisplayTransitionCallee = firmware_transition_second;
#[cfg(target_os = "none")]
static mut DISPLAY_TRANSITION_FINISH: DisplayTransitionCallee = firmware_transition_finish;
#[cfg(not(target_os = "none"))]
static mut DISPLAY_TRANSITION_FIRST: DisplayTransitionCallee = missing_display_transition_callee;
#[cfg(not(target_os = "none"))]
static mut DISPLAY_TRANSITION_SECOND: DisplayTransitionCallee = missing_display_transition_callee;
#[cfg(not(target_os = "none"))]
static mut DISPLAY_TRANSITION_FINISH: DisplayTransitionCallee = missing_display_transition_callee;

/// apply_display_transition — original: `FUN_0828d774` @ `0x0828d774`
/// (124 bytes, `0x0828d774..0x0828d7f0`: 120 instruction bytes followed by
/// the literal `0x089cc8a0`; the next function opens at `0x0828d7f0`).
/// **3 direct `bl` calls, all unconditional, plus one tail `b`** — verified
/// from the raw ARM words; Ghidra's 204-byte extent absorbs the next routine.
///
/// Validates two boolean mode values before any side effect, defaults a null
/// display to `display_get(1)`, stores the values in bytes +2 and +1 of the
/// shared pending-state block, then invokes the two direct display routines.
/// It tail-calls `0x081d8ed0` with whether `finish_mode` is zero, preserving
/// that routine's status. Invalid modes return the incoming display word.
///
/// # Deliberate deviations
///
/// The stock RW block is represented by [`DISPLAY_PENDING_STATE`]. The three
/// unported callees remain verified-address volatile seams; host tests install
/// recorders rather than assigning identities beyond their observed ABI.
///
/// # Safety
///
/// A non-null `display` must be a live [`Display`], as required by all three
/// unchecked retailOS callees.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn apply_display_transition(
    mut display: *mut Display,
    primary_mode: u32,
    secondary_mode: u32,
    finish_mode: u32,
) -> usize {
    if primary_mode > 1 || secondary_mode > 1 {
        return display as usize;
    }

    if display.is_null() {
        display = display_get(SECONDARY_DISPLAY_ID as u32);
    }

    ptr::write_volatile(
        ptr::addr_of_mut!(DISPLAY_PENDING_STATE.transition_primary),
        primary_mode as u8,
    );
    ptr::write_volatile(
        ptr::addr_of_mut!(DISPLAY_PENDING_STATE.transition_secondary),
        secondary_mode as u8,
    );

    let first = ptr::read_volatile(ptr::addr_of!(DISPLAY_TRANSITION_FIRST));
    first(display, primary_mode);
    let second = ptr::read_volatile(ptr::addr_of!(DISPLAY_TRANSITION_SECOND));
    second(display, secondary_mode);
    let finish = ptr::read_volatile(ptr::addr_of!(DISPLAY_TRANSITION_FINISH));
    finish(display, (finish_mode == 0) as u32) as usize
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::MutexGuard;
    static mut FORWARDED: Option<(*mut Display, u8, [u8; 4])> = None;

    unsafe extern "C" fn record_pending_nibbles(
        display: *mut Display,

        selector: u8,
        nibbles: *const u8,
    ) {
        FORWARDED = Some((display, selector, [
            nibbles.read_volatile(),
            nibbles.add(1).read_volatile(),
            nibbles.add(2).read_volatile(),
            nibbles.add(3).read_volatile(),
        ]));
    }
    static mut TRANSITION_CALLS: [Option<(*mut Display, u32)>; 3] = [None; 3];

    unsafe extern "C" fn record_transition_first(display: *mut Display, value: u32) -> u32 {
        TRANSITION_CALLS[0] = Some((display, value));
        3
    }

    unsafe extern "C" fn record_transition_second(display: *mut Display, value: u32) -> u32 {
        TRANSITION_CALLS[1] = Some((display, value));
        4
    }

    unsafe extern "C" fn record_transition_finish(display: *mut Display, value: u32) -> u32 {
        TRANSITION_CALLS[2] = Some((display, value));
        7
    }

    unsafe fn install_transition_recorders() {
        DISPLAY_TRANSITION_FIRST = record_transition_first;
        DISPLAY_TRANSITION_SECOND = record_transition_second;
        DISPLAY_TRANSITION_FINISH = record_transition_finish;
        TRANSITION_CALLS = [None; 3];
    }

    unsafe fn restore_transition_recorders() {
        DISPLAY_TRANSITION_FIRST = missing_display_transition_callee;
        DISPLAY_TRANSITION_SECOND = missing_display_transition_callee;
        DISPLAY_TRANSITION_FINISH = missing_display_transition_callee;
    }

    #[test]
    fn transition_validates_before_mutation_and_preserves_tail_status() {
        let guard = install_recorder();
        let display = 0x1234usize as *mut Display;

        unsafe {
            DISPLAY_PENDING_STATE.transition_primary = 1;
            DISPLAY_PENDING_STATE.transition_secondary = 1;
            install_transition_recorders();

            assert_eq!(apply_display_transition(display, 2, 0, 0), display as usize);
            assert_eq!(DISPLAY_PENDING_STATE.transition_primary, 1);
            assert_eq!(DISPLAY_PENDING_STATE.transition_secondary, 1);
            assert_eq!(TRANSITION_CALLS, [None; 3]);

            assert_eq!(apply_display_transition(display, 1, 0, 0), 7);
            assert_eq!(DISPLAY_PENDING_STATE.transition_primary, 1);
            assert_eq!(DISPLAY_PENDING_STATE.transition_secondary, 0);
            assert_eq!(TRANSITION_CALLS, [
                Some((display, 1)),
                Some((display, 0)),
                Some((display, 1)),
            ]);
            restore_transition_recorders();
        }
        restore_recorder(guard);
    }

    #[test]
    fn transition_uses_secondary_display_for_null_input() {
        let display_guard = crate::drivers::display::DISPLAY_TEST_LOCK.lock();
        let guard = install_recorder();

        unsafe {
            crate::drivers::display::SECONDARY_DISPLAY_GUARD = 1;
            let secondary = ptr::addr_of_mut!(crate::drivers::display::SECONDARY_DISPLAY);
            install_transition_recorders();

            assert_eq!(apply_display_transition(ptr::null_mut(), 0, 1, 2), 7);
            assert_eq!(TRANSITION_CALLS, [
                Some((secondary, 0)),
                Some((secondary, 1)),
                Some((secondary, 0)),
            ]);

            restore_transition_recorders();
            crate::drivers::display::SECONDARY_DISPLAY_GUARD = 0;
        }
        restore_recorder(guard);
        drop(display_guard);
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = DISPLAY_PENDING_NIBBLES_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPLAY_PENDING_STATE = DisplayPendingState {
                selector: 0,
                transition_secondary: 0,
                transition_primary: 0,
            };
            DISPLAY_PENDING_NIBBLES = [0; 4];
            DISPLAY_SET_PENDING_NIBBLES = record_pending_nibbles;
            FORWARDED = None;
        }
        guard
    }

    fn restore_recorder(guard: MutexGuard<'static, ()>) {
        unsafe { DISPLAY_SET_PENDING_NIBBLES = missing_display_set_pending_nibbles };
        drop(guard);
    }

    #[test]
    fn preserves_sentinel_fields_and_forwards_retained_configuration() {
        let guard = install_recorder();
        let display = 0x1234usize as *mut Display;

        unsafe {
            DISPLAY_PENDING_STATE.selector = 0;
            DISPLAY_PENDING_NIBBLES = [1, 2, 3, 4];
            configure_display_pending_nibbles(display, 1, -1, 15, -1, 0);

            assert_eq!(DISPLAY_PENDING_STATE.selector, 1);
            assert_eq!(DISPLAY_PENDING_NIBBLES, [1, 15, 3, 0]);
            assert_eq!(FORWARDED, Some((display, 1, [1, 15, 3, 0])));
        }
        restore_recorder(guard);
    }

    #[test]
    fn invalid_input_changes_nothing_and_skips_the_display_callee() {
        let guard = install_recorder();
        let display = 0x1234usize as *mut Display;

        unsafe {
            DISPLAY_PENDING_STATE.selector = 1;
            DISPLAY_PENDING_NIBBLES = [4, 5, 6, 7];
            configure_display_pending_nibbles(display, 0, 4, 16, 6, 7);

            assert_eq!(DISPLAY_PENDING_STATE.selector, 1);
            assert_eq!(DISPLAY_PENDING_NIBBLES, [4, 5, 6, 7]);
            assert_eq!(FORWARDED, None);
        }
        restore_recorder(guard);
    }

    #[test]
    fn null_display_defaults_to_the_secondary_singleton() {
        let display_guard = crate::drivers::display::DISPLAY_TEST_LOCK.lock();
        let guard = install_recorder();

        unsafe {
            crate::drivers::display::SECONDARY_DISPLAY_GUARD = 1;
            let secondary = ptr::addr_of_mut!(crate::drivers::display::SECONDARY_DISPLAY);
            configure_display_pending_nibbles(ptr::null_mut(), -1, -1, -1, -1, -1);

            assert_eq!(FORWARDED, Some((secondary, 0, [0; 4])));
            crate::drivers::display::SECONDARY_DISPLAY_GUARD = 0;
        }
        restore_recorder(guard);
        drop(display_guard);
    }
}
