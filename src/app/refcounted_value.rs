//! `release_refcounted_value` — retailOS `FUN_082739e0` @ `0x082739e0`.
//!
//! ## Extent and call sites, byte-verified
//!
//! The function is exactly **52 bytes**: thirteen ARM instruction words from
//! `0x082739e0` through `0x08273a10`; `0x08273a14` begins its separately
//! linked retain sibling. Decoding every ARM B/BL word in `osos.dec` finds
//! **28** direct call sites, all `blne`; there are no unconditional or other
//! predicated BL forms, tail branches, or DATA-word references. Each caller
//! checks its value pointer first, so the stock callee deliberately has no
//! NULL guard.
//!
//! ## Algorithm
//!
//! The low byte of word `+0x14` contains flag bits 0..1 and the remaining bits
//! are a reference count in units of four. If flag bit 1 is clear, return. If
//! it is set, subtract four from the whole word with ARM's wrapping arithmetic.
//! When the count bits then become zero, invoke the deleting destructor in
//! vtable slot `+0x04` with the object as its only argument.
//!
//! ## Deliberate deviation
//!
//! Target builds load the 32-bit vtable word and dispatch its `+0x04` word
//! exactly. On 64-bit host tests, an ARM vtable function address cannot fit in
//! that word, so only the drain-dispatch observation uses a test-only atomic
//! callback; production target code has no seam.

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(target_os = "none"))]
static HOST_DELETING_DESTRUCTOR: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "none")]
unsafe fn call_deleting_destructor(object: *mut u8) {
    let vtable = object.cast::<u32>().read_volatile();
    let entry = (vtable as *const u32).add(1).read_volatile();
    let deleting_destructor: unsafe extern "C" fn(*mut u8) = core::mem::transmute(entry as usize);
    deleting_destructor(object);
}

#[cfg(not(target_os = "none"))]
unsafe fn call_deleting_destructor(object: *mut u8) {
    let entry = HOST_DELETING_DESTRUCTOR.load(Ordering::SeqCst);
    if entry != 0 {
        let deleting_destructor: unsafe extern "C" fn(*mut u8) = core::mem::transmute(entry);
        deleting_destructor(object);
    }
}

/// release_refcounted_value — retailOS `FUN_082739e0` @ `0x082739e0` (52
/// bytes; 28 binary-verified `blne` call sites).
///
/// Releases one unit from the flags/refcount word at target offset `+0x14`.
/// Flag bit 1 gates the decrement. A resulting zero count dispatches the
/// deleting destructor through vtable slot `+0x04`. The firmware has no NULL
/// guard: callers must pass a live, 4-byte-aligned object containing at least
/// 0x18 bytes and, on a draining release, a valid vtable and deleting
/// destructor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_refcounted_value(object: *mut u8) {
    let flags_byte = object.add(0x14);
    if flags_byte.read_volatile() & 2 == 0 {
        return;
    }

    let flags_word = flags_byte.cast::<u32>();
    let flags = flags_word.read_volatile().wrapping_sub(4);
    flags_word.write_volatile(flags);
    if flags & !3 != 0 {
        return;
    }

    call_deleting_destructor(object);
}

#[cfg(test)]
fn set_host_deleting_destructor(destructor: Option<unsafe extern "C" fn(*mut u8)>) {
    let entry = destructor.map_or(0, |function| function as usize);
    HOST_DELETING_DESTRUCTOR.store(entry, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static DELETIONS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recording_destructor(_object: *mut u8) {
        DELETIONS.fetch_add(1, Ordering::SeqCst);
    }

    fn object_with_flags(flags: u32) -> [u32; 6] {
        [0xdead_beef, 0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, flags]
    }

    #[test]
    fn flag_bit_one_clear_leaves_everything_unchanged() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        set_host_deleting_destructor(Some(recording_destructor));
        DELETIONS.store(0, Ordering::SeqCst);

        for flags in [0, 1, 4, 0xffff_fffd] {
            let mut object = object_with_flags(flags);
            let before = object;
            unsafe { release_refcounted_value(object.as_mut_ptr().cast()) };
            assert_eq!(object, before, "flags {flags:#x}");
        }
        assert_eq!(DELETIONS.load(Ordering::SeqCst), 0);
        set_host_deleting_destructor(None);
    }

    #[test]
    fn a_live_count_loses_exactly_one_unit_and_preserves_flag_bits() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        set_host_deleting_destructor(Some(recording_destructor));
        DELETIONS.store(0, Ordering::SeqCst);
        let mut object = object_with_flags(0b1111);

        unsafe { release_refcounted_value(object.as_mut_ptr().cast()) };

        assert_eq!(object[5], 0b1011, "the full +0x14 word subtracts four");
        assert_eq!(DELETIONS.load(Ordering::SeqCst), 0, "count bits remain live");
        set_host_deleting_destructor(None);
    }

    #[test]
    fn draining_the_last_count_dispatches_the_deleting_destructor() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        set_host_deleting_destructor(Some(recording_destructor));
        DELETIONS.store(0, Ordering::SeqCst);
        let mut object = object_with_flags(0b111);

        unsafe { release_refcounted_value(object.as_mut_ptr().cast()) };

        assert_eq!(object[5], 0b11, "only the two flag bits remain");
        assert_eq!(DELETIONS.load(Ordering::SeqCst), 1);
        set_host_deleting_destructor(None);
    }

    #[test]
    fn count_underflow_stays_live_under_arm_wrapping_arithmetic() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        set_host_deleting_destructor(Some(recording_destructor));
        DELETIONS.store(0, Ordering::SeqCst);
        let mut object = object_with_flags(0b10);

        unsafe { release_refcounted_value(object.as_mut_ptr().cast()) };

        assert_eq!(object[5], 0xffff_fffe);
        assert_eq!(DELETIONS.load(Ordering::SeqCst), 0);
        set_host_deleting_destructor(None);
    }
}
