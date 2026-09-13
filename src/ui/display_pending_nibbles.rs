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

/// Original global byte at `0x089cc8a0`; `-1` leaves it unchanged.
static mut DISPLAY_PENDING_SELECTOR: u8 = 0;
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
        ptr::write_volatile(ptr::addr_of_mut!(DISPLAY_PENDING_SELECTOR), selector as u8);
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

    let retained_selector = ptr::read_volatile(ptr::addr_of!(DISPLAY_PENDING_SELECTOR));
    let retained_nibbles = ptr::addr_of!(DISPLAY_PENDING_NIBBLES).cast::<u8>();
    set_display_pending_nibbles(display, retained_selector, retained_nibbles);
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

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = DISPLAY_PENDING_NIBBLES_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DISPLAY_PENDING_SELECTOR = 0;
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
            DISPLAY_PENDING_SELECTOR = 0;
            DISPLAY_PENDING_NIBBLES = [1, 2, 3, 4];
            configure_display_pending_nibbles(display, 1, -1, 15, -1, 0);

            assert_eq!(DISPLAY_PENDING_SELECTOR, 1);
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
            DISPLAY_PENDING_SELECTOR = 1;
            DISPLAY_PENDING_NIBBLES = [4, 5, 6, 7];
            configure_display_pending_nibbles(display, 0, 4, 16, 6, 7);

            assert_eq!(DISPLAY_PENDING_SELECTOR, 1);
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
