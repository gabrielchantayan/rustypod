//! Scheduler label lookup — `FUN_08399624` @ `0x08399624`.
//!
//! Raw `osos.dec` has 64 bytes of ARM instructions followed by a 12-byte
//! literal pool, so its binary extent is 76 bytes (`0x08399624..0x08399670`);
//! the following independent function starts at `0x08399670`. Decoding every
//! ARM `B`/`BL` word finds 10 direct callers, all unconditional `bl` (none
//! predicated): `0x082bef18`, `0x082bef74`, `0x082bf348`, `0x082bf4cc`,
//! `0x082bf9a4`, `0x082bf9c8`, `0x082bfd3c`, `0x082c0050`, `0x082c0344`, and
//! `0x082d0bf8`.
//!
//! # Algorithm
//!
//! This scheduler-diagnostic helper maps an integer identifier to its label
//! word. If the identifier is signed-less-than-or-equal to the runtime bound
//! at `0x083e89f0`, it returns `direct_base + identifier * 17`, where
//! `direct_base` is the runtime word at `0x083e89dc`. Otherwise it asks the
//! unported 80-entry registered-label table lookup at `0x080632e0` to write a
//! label word into a stack slot. A successful lookup supplies that word; an
//! unsuccessful lookup returns the runtime fallback word at `0x083e237c`.
//! The raw ARM has no null guard around its stack output because it owns that
//! valid slot, and it deliberately uses signed comparison but wrapping
//! register arithmetic for the direct path.
//!
//! Deliberate deviation: none on target. Host tests substitute the three
//! runtime words and the unported lookup seam; target builds retain volatile
//! reads from the three retailOS addresses and dispatch to `0x080632e0`.

/// ABI of the unported registered-label table lookup at `0x080632e0`.
pub type SchedulerLabelFind = unsafe extern "C" fn(identifier: i32, out_label: *mut u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_scheduler_label_find(identifier: i32, out_label: *mut u32) -> u32 {
    let find: SchedulerLabelFind = unsafe { core::mem::transmute(0x0806_32e0usize) };
    unsafe { find(identifier, out_label) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scheduler_label_find(_identifier: i32, _out_label: *mut u32) -> u32 {
    panic!("scheduler_label_lookup requires registered-label lookup 0x080632e0")
}

#[cfg(target_os = "none")]
pub(crate) const DEFAULT_SCHEDULER_LABEL_FIND: SchedulerLabelFind = firmware_scheduler_label_find;
#[cfg(not(target_os = "none"))]
pub(crate) const DEFAULT_SCHEDULER_LABEL_FIND: SchedulerLabelFind = missing_scheduler_label_find;

/// The unported registered-label lookup. Target builds call retailOS directly;
/// host tests replace this callback to model the success and fallback paths.
pub static mut SCHEDULER_LABEL_FIND: SchedulerLabelFind = DEFAULT_SCHEDULER_LABEL_FIND;

const DIRECT_LIMIT_ADDRESS: usize = 0x083e_89f0;
const DIRECT_BASE_ADDRESS: usize = 0x083e_89dc;
const FALLBACK_LABEL_ADDRESS: usize = 0x083e_237c;

#[cfg(not(target_os = "none"))]
static mut HOST_DIRECT_LIMIT: i32 = 0xe1c2_30b6u32 as i32;
#[cfg(not(target_os = "none"))]
static mut HOST_DIRECT_BASE: u32 = 0xe590_c000;
#[cfg(not(target_os = "none"))]
static mut HOST_FALLBACK_LABEL: u32 = 0xebff_ffab;

#[inline(always)]
unsafe fn runtime_i32(address: usize) -> i32 {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::read_volatile(address as *const i32) }
    }
    #[cfg(not(target_os = "none"))]
    {
        match address {
            DIRECT_LIMIT_ADDRESS => unsafe { core::ptr::addr_of!(HOST_DIRECT_LIMIT).read_volatile() },
            _ => unreachable!(),
        }
    }
}

#[inline(always)]
unsafe fn runtime_u32(address: usize) -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::read_volatile(address as *const u32) }
    }
    #[cfg(not(target_os = "none"))]
    {
        match address {
            DIRECT_BASE_ADDRESS => unsafe { core::ptr::addr_of!(HOST_DIRECT_BASE).read_volatile() },
            FALLBACK_LABEL_ADDRESS => unsafe { core::ptr::addr_of!(HOST_FALLBACK_LABEL).read_volatile() },
            _ => unreachable!(),
        }
    }
}

/// scheduler_label_lookup — original: `FUN_08399624` @ `0x08399624` (76 bytes).
///
/// Returns the direct 17-byte label-table address for an identifier at or
/// below the signed runtime bound. Higher identifiers are resolved through the
/// registered-label lookup; unmapped identifiers return the fallback label.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn scheduler_label_lookup(identifier: i32) -> u32 {
    let direct_limit = unsafe { runtime_i32(DIRECT_LIMIT_ADDRESS) };
    if identifier <= direct_limit {
        let direct_base = unsafe { runtime_u32(DIRECT_BASE_ADDRESS) };
        direct_base.wrapping_add((identifier as u32).wrapping_mul(17))
    } else {
        let mut label = 0;
        let find = unsafe { core::ptr::addr_of_mut!(SCHEDULER_LABEL_FIND).read_volatile() };
        if unsafe { find(identifier, &mut label) } != 0 {
            label
        } else {
            unsafe { runtime_u32(FALLBACK_LABEL_ADDRESS) }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use crate::testing::SCHEDULER_LABEL_FIND_TEST_LOCK;
    use std::sync::MutexGuard;
    static mut LOOKUP_CALLS: u32 = 0;
    static mut LOOKUP_IDENTIFIER: i32 = 0;
    static mut LOOKUP_SUCCESS: u32 = 0;
    static mut LOOKUP_LABEL: u32 = 0;

    unsafe extern "C" fn recording_scheduler_label_find(identifier: i32, out_label: *mut u32) -> u32 {
        unsafe {
            LOOKUP_CALLS += 1;
            LOOKUP_IDENTIFIER = identifier;
            if LOOKUP_SUCCESS != 0 {
                out_label.write(LOOKUP_LABEL);
            }
            LOOKUP_SUCCESS
        }
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(SCHEDULER_LABEL_FIND).write(DEFAULT_SCHEDULER_LABEL_FIND);
                ptr::addr_of_mut!(HOST_DIRECT_LIMIT).write(0xe1c2_30b6u32 as i32);
                ptr::addr_of_mut!(HOST_DIRECT_BASE).write(0xe590_c000);
                ptr::addr_of_mut!(HOST_FALLBACK_LABEL).write(0xebff_ffab);
            }
        }
    }

    fn install_lookup() -> (MutexGuard<'static, ()>, Reset) {
        let guard = SCHEDULER_LABEL_FIND_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            ptr::addr_of_mut!(SCHEDULER_LABEL_FIND).write(recording_scheduler_label_find);
            ptr::addr_of_mut!(LOOKUP_CALLS).write(0);
            ptr::addr_of_mut!(LOOKUP_IDENTIFIER).write(0);
            ptr::addr_of_mut!(LOOKUP_SUCCESS).write(0);
            ptr::addr_of_mut!(LOOKUP_LABEL).write(0);
        }
        (guard, Reset)
    }

    #[test]
    fn direct_path_includes_bound_and_uses_signed_wrapping_math() {
        let (_guard, _reset) = install_lookup();
        unsafe {
            ptr::addr_of_mut!(HOST_DIRECT_LIMIT).write(3);
            ptr::addr_of_mut!(HOST_DIRECT_BASE).write(0xffff_fff8);
        }

        for identifier in [-1, 0, 1, 3] {
            let expected = 0xffff_fff8u32.wrapping_add((identifier as u32).wrapping_mul(17));
            assert_eq!(scheduler_label_lookup(identifier), expected);
        }
        assert_eq!(unsafe { LOOKUP_CALLS }, 0);
    }

    #[test]
    fn higher_identifier_forwards_to_registered_label_lookup() {
        let (_guard, _reset) = install_lookup();
        unsafe {
            ptr::addr_of_mut!(HOST_DIRECT_LIMIT).write(i32::MIN);
            ptr::addr_of_mut!(LOOKUP_SUCCESS).write(1);
            ptr::addr_of_mut!(LOOKUP_LABEL).write(0x08a1_2345);
        }

        assert_eq!(scheduler_label_lookup(i32::MAX), 0x08a1_2345);
        assert_eq!(unsafe { LOOKUP_CALLS }, 1);
        assert_eq!(unsafe { LOOKUP_IDENTIFIER }, i32::MAX);
    }

    #[test]
    fn failed_registered_lookup_returns_fallback_word() {
        let (_guard, _reset) = install_lookup();
        unsafe {
            ptr::addr_of_mut!(HOST_DIRECT_LIMIT).write(-2);
            ptr::addr_of_mut!(HOST_FALLBACK_LABEL).write(0xfeed_face);
        }

        assert_eq!(scheduler_label_lookup(-1), 0xfeed_face);
        assert_eq!(unsafe { LOOKUP_CALLS }, 1);
        assert_eq!(unsafe { LOOKUP_IDENTIFIER }, -1);
    }
}
