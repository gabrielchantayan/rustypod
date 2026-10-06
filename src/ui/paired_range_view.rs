//! Paired-element range view — `FUN_0815c9ac` @ `0x0815c9ac`.
//!
//! True extent: 76 bytes, 68 code bytes through the return at 0x0815c9ec
//! and literals at 0x0815c9f0/4; next function starts at 0x0815c9f8.
//! Whole-image aligned A32 decoding verifies two inbound plain BLs
//! (0x0815be5c, 0x081b8e80), three outbound plain BLs, and no predicated
//! BLs in either set.
//!
//! Constructs the range base with all five arguments, installs vtable
//! 0x089877ac, constructs two 0xd4-byte elements at +0xc4 using the raw
//! callback word 0x08150f30, then derives the object pointer from the array
//! helper result. Copies spec +0x68 to that object's +0xbc, initializes its
//! paired-element state via 0x0815bf5c, and returns the derived pointer.
//! Deviations: restores Ghidra's lost arguments and pointer return. The
//! element callback is opaque data, not an invented function identity.
//! The unported initializer has a fixed-address target seam; host use must
//! install an implementation. Target layout uses aligned u32 words.

use crate::app::resource_chain::ResourceProvider;
use crate::runtime::cpp_array_construct::cpp_array_construct;
use crate::ui::range_view::{range_view_construct, RangeView, RangeViewSpec};

#[repr(C)]
pub struct PairedRangeViewSpec {
    pub range: RangeViewSpec,
    /// Copied verbatim to object +0xbc before state initialization.
    pub configuration: u32,
}

const _: [u8; 0x6c] = [0; core::mem::size_of::<PairedRangeViewSpec>()];

/// The verified single-object ABI of the unported initializer @ 0x0815bf5c.
pub type InitializePairedRangeState = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn initialize_paired_range_state(view: *mut u32) {
    let initialize: InitializePairedRangeState = core::mem::transmute(0x0815_bf5cusize);
    initialize(view);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn initialize_paired_range_state(_view: *mut u32) {
    panic!("install PAIRED_RANGE_STATE_INITIALIZE before host use");
}

pub static mut PAIRED_RANGE_STATE_INITIALIZE: InitializePairedRangeState =
    initialize_paired_range_state;

#[inline(always)]
unsafe fn copy_configuration(array_result: *mut u32, spec: *const PairedRangeViewSpec) -> *mut u32 {
    let view = array_result.sub(0xc4 / 4);
    view.add(0xbc / 4).write_volatile((*spec).configuration);
    view
}

/// Construct a paired range view in caller-owned 0x2dc-byte storage.
///
/// # Safety
/// Storage must be writable and four-byte aligned; spec must be readable.
/// Base and array dependencies must accept the arguments. The array result
/// minus 0xc4 must designate a writable object accepted by the initializer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn paired_range_view_construct(
    view: *mut u32,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const PairedRangeViewSpec,
) -> *mut u32 {
    let base = range_view_construct(view.cast::<RangeView>(), resources, controller, parent,
        core::ptr::addr_of!((*spec).range)).cast::<u32>();
    base.write_volatile(0x0898_77ac);
    let array = cpp_array_construct(base.add(0xc4 / 4), 0x0815_0f30, 0xd4, 2);
    let result = copy_configuration(array, spec);
    let initialize = core::ptr::addr_of!(PAIRED_RANGE_STATE_INITIALIZE).read_volatile();
    initialize(result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_verbatim_and_only_changes_the_returned_object_word() {
        for configuration in [0, 1, 0x8000_0000, u32::MAX] {
            let mut storage = [0xa5a5_a5a5u32; 0x2dc / 4 * 2];
            let mut spec: PairedRangeViewSpec = unsafe { core::mem::zeroed() };
            spec.configuration = configuration;
            // A helper may return a different base; do not write the input
            // object's configuration or assume the helper returns its input.
            let result = unsafe { storage.as_mut_ptr().add(0x2dc / 4) };
            let array = unsafe { result.add(0xc4 / 4) };
            assert_eq!(unsafe { copy_configuration(array, &spec) }, result);
            let mut expected = [0xa5a5_a5a5u32; 0x2dc / 4 * 2];
            expected[(0x2dc + 0xbc) / 4] = configuration;
            assert_eq!(storage, expected);
        }
    }
}
