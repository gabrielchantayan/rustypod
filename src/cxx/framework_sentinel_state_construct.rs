//! Framework sentinel-state constructor @ 0x08275cd4 (`FUN_08275cd4`).
//!
//! True extent: 40 bytes [0x08275cd4, 0x08275cfc), comprising 36 bytes
//! of instructions and the vtable literal 0x089a5ffc at 0x08275cf8.
//! The next function is a destructor veneer branching to 0x08275bc8.
//! Raw-image scan: two incoming plain BLs (0x081440e4, 0x0816bfec),
//! zero predicated BLs; one outgoing plain BL at 0x08275cd8 to the
//! already-ported root constructor 0x08275bb8, zero predicated BLs.
//!
//! Construct the framework root, overwrite its vtable, set the word at
//! +4 to the all-ones sentinel, and clear byte +8. Return the root's
//! result in r0. Both callers replace this vtable with a derived one.
//! The sentinel and flag's higher-level roles are not established.
//! Deviations: none; fixed-width fields preserve target offsets on hosts,
//! and volatile stores preserve the root/vtable write sequence. Bytes
//! +9..+11 and any derived state remain untouched.

use crate::cxx::observable_array::{framework_object_construct, FrameworkObject};

pub const FRAMEWORK_SENTINEL_STATE_VTABLE: u32 = 0x089a_5ffc;

#[repr(C)]
pub struct FrameworkSentinelState {
    pub base: FrameworkObject,
    pub sentinel: u32,
    pub flag: u8,
    pub untouched_09_0b: [u8; 3],
}

/// # Safety
/// `storage` must point to aligned, writable storage for the entire prefix.
/// No NULL check is performed by retailOS or this port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn framework_sentinel_state_construct(
    storage: *mut FrameworkSentinelState,
) -> *mut FrameworkSentinelState {
    let this = framework_object_construct(storage.cast()).cast::<FrameworkSentinelState>();
    core::ptr::addr_of_mut!((*this).base.vtable).write_volatile(FRAMEWORK_SENTINEL_STATE_VTABLE);
    core::ptr::addr_of_mut!((*this).sentinel).write_volatile(u32::MAX);
    core::ptr::addr_of_mut!((*this).flag).write_volatile(0);
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_prefix_without_clobbering_padding_or_derived_state() {
        // Word fixtures independently encode the firmware's byte stores.
        for fill in [0u32, u32::MAX, 0xa596_3cc7, 0x1234_5678] {
            let mut words = [fill; 5];
            let mut expected = words;
            expected[1] = FRAMEWORK_SENTINEL_STATE_VTABLE;
            expected[2] = u32::MAX;
            expected[3] &= 0xffff_ff00;
            let storage = unsafe { words.as_mut_ptr().add(1).cast::<FrameworkSentinelState>() };
            let result = unsafe { framework_sentinel_state_construct(storage) };
            assert_eq!(result, storage);
            assert_eq!(words, expected);
        }
    }

    #[test]
    fn reconstructing_restores_sentinel_and_flag_but_preserves_other_bytes() {
        let mut state = FrameworkSentinelState {
            base: FrameworkObject { vtable: 0 }, sentinel: 42, flag: 0xff,
            untouched_09_0b: [0x12, 0x34, 0x56],
        };
        unsafe { framework_sentinel_state_construct(&mut state); }
        state.sentinel = 0;
        state.flag = 1;
        state.untouched_09_0b[1] = 0xab;
        unsafe { framework_sentinel_state_construct(&mut state); }
        assert_eq!(state.base.vtable, FRAMEWORK_SENTINEL_STATE_VTABLE);
        assert_eq!(state.sentinel, u32::MAX);
        assert_eq!(state.flag, 0);
        assert_eq!(state.untouched_09_0b, [0x12, 0xab, 0x56]);
    }
}
