//! Framework data-span state constructor @ 0x081440d8 (`FUN_081440d8`).
//!
//! True extent: 76 bytes [0x081440d8, 0x08144124): 72 instruction bytes
//! and vtable literal 0x089860b0 at 0x08144120. Next function is the
//! destructor at 0x08144124. Whole-image ARM word scan: two incoming
//! plain BLs (0x0807f7ac, 0x081030f0), zero predicated BLs; one outgoing
//! plain BL at 0x081440e4 to framework_sentinel_state_construct
//! (0x08275cd4), zero predicated BLs.
//!
//! Construct the sentinel prefix, install the derived vtable, retain
//! the supplied data address and extent at +12/+16, clear three state
//! words and set the trailing bytes to [24, 0, 0, 0]. Return the base
//! constructor's result unchanged. The caller at 0x0810301c supplies a
//! data address and a virtual read result; other state roles remain
//! unestablished. Deviations: none. Fixed-width fields and volatile
//! stores preserve ARM layout and write order, including prefix padding.

use crate::cxx::framework_sentinel_state_construct::{
    framework_sentinel_state_construct, FrameworkSentinelState,
};

pub const FRAMEWORK_DATA_SPAN_STATE_VTABLE: u32 = 0x0898_60b0;

#[repr(C)]
pub struct FrameworkDataSpanState {
    pub base: FrameworkSentinelState,
    pub data: u32,
    pub extent: u32,
    pub state_14: u32,
    pub state_18: u32,
    pub state_1c: u32,
    pub mode: u8,
    pub flag_21: u8,
    pub flag_22: u8,
    pub flag_23: u8,
}

/// # Safety
/// `storage` must be word-aligned writable storage for the entire object.
/// The supplied data address is retained, not dereferenced or validated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn framework_data_span_state_construct(
    storage: *mut FrameworkDataSpanState, data: u32, extent: u32,
) -> *mut FrameworkDataSpanState {
    let this = framework_sentinel_state_construct(storage.cast()).cast::<FrameworkDataSpanState>();
    core::ptr::addr_of_mut!((*this).base.base.vtable).write_volatile(FRAMEWORK_DATA_SPAN_STATE_VTABLE);
    core::ptr::addr_of_mut!((*this).state_14).write_volatile(0);
    core::ptr::addr_of_mut!((*this).data).write_volatile(data);
    core::ptr::addr_of_mut!((*this).extent).write_volatile(extent);
    core::ptr::addr_of_mut!((*this).state_18).write_volatile(0);
    core::ptr::addr_of_mut!((*this).state_1c).write_volatile(0);
    core::ptr::addr_of_mut!((*this).mode).write_volatile(24);
    core::ptr::addr_of_mut!((*this).flag_21).write_volatile(0);
    core::ptr::addr_of_mut!((*this).flag_22).write_volatile(0);
    core::ptr::addr_of_mut!((*this).flag_23).write_volatile(0);
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_dirty_storage_preserving_padding_and_bounds() {
        for fill in [0u32, u32::MAX, 0xa596_3cc7] {
            for (data, extent) in [(0, 0), (0, u32::MAX), (0xffff_ffff, 0), (0x0800_0001, 0x8000_0000)] {
                let mut words = [fill; 11];
                let mut expected = words;
                expected[1] = FRAMEWORK_DATA_SPAN_STATE_VTABLE;
                expected[2] = u32::MAX;
                expected[3] &= 0xffff_ff00;
                expected[4] = data;
                expected[5] = extent;
                expected[6..9].fill(0);
                expected[9] = 24;
                let storage = unsafe { words.as_mut_ptr().add(1).cast() };
                assert_eq!(unsafe { framework_data_span_state_construct(storage, data, extent) }, storage);
                assert_eq!(words, expected);
            }
        }
    }

    #[test]
    fn reconstructing_replaces_span_and_clears_previous_state() {
        let mut words = [0x1234_56ffu32; 9];
        let storage = words.as_mut_ptr().cast();
        unsafe { framework_data_span_state_construct(storage, 0x0800_0000, 4096); }
        words[1] = 0;
        words[2] = 0xabcd_ef01;
        words[5..9].fill(u32::MAX);
        unsafe { framework_data_span_state_construct(storage, 0, 0); }
        assert_eq!(words, [FRAMEWORK_DATA_SPAN_STATE_VTABLE, u32::MAX, 0xabcd_ef00, 0, 0, 0, 0, 0, 24]);
    }
}
