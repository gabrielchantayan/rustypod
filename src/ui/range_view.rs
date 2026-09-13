//! The constructor of the shared range-value view layer. Six concrete
//! Silver UI view constructors chain through it before installing their own
//! vtables. Its immediately preceding sibling clamps the current value
//! (+0xa8) to the inclusive minimum/maximum fields (+0xac/+0xb0), which
//! identifies this layer's three derived words as the range state.
//!
//! Raw ARM at 0x0812b94c is 64 bytes: 60 code bytes followed by the vtable
//! literal 0x08983928 at 0x0812b988; the separately linked deleting
//! destructor starts at 0x0812b98c. Decoding every ARM B/BL immediate in
//! osos.dec finds six direct `bl` callers, all unconditional: 0x0815c9b8,
//! 0x0816bc74, 0x081860e8, 0x081ca15c, 0x0820fa64, and 0x0828c444.

use crate::app::resource_chain::ResourceProvider;
use crate::ui::view_base::{view_base_construct, ViewBase, ViewSpec};

/// The ROM address written to the range-view vtable word by the constructor's
/// literal pool at 0x0812b988. The image carries stale RW data there rather
/// than callable table entries, and this port does not dispatch through it.
pub const RANGE_VIEW_VTABLE_ADDRESS: u32 = 0x0898_3928;

/// The 0x68-byte specification consumed by [`range_view_construct`].
///
/// `base.word_58` is both the generic view spec's final word and this
/// class's configuration word. The remaining three words seed the range.
#[repr(C)]
pub struct RangeViewSpec {
    /// +0x00..+0x5c — generic grand-base view specification.
    pub base: ViewSpec,
    /// +0x5c — initial current range value.
    pub initial_value: u32,
    /// +0x60 — inclusive lower bound.
    pub minimum: u32,
    /// +0x64 — inclusive upper bound.
    pub maximum: u32,
}

const _: [u8; 0x68] = [0; core::mem::size_of::<RangeViewSpec>()];
const _: [u8; 0x5c] = [0; core::mem::offset_of!(RangeViewSpec, initial_value)];
const _: [u8; 0x60] = [0; core::mem::offset_of!(RangeViewSpec, minimum)];
const _: [u8; 0x64] = [0; core::mem::offset_of!(RangeViewSpec, maximum)];

/// The 0xb4-byte grand-base view plus its range state.
#[repr(C)]
pub struct RangeView {
    /// +0x00..+0xa4 — constructed by [`view_base_construct`].
    pub base: ViewBase,
    /// +0xa4 — spec +0x58, copied without the grand-base's flag gate.
    pub config: u32,
    /// +0xa8 — spec +0x5c; clamped by the sibling range setter.
    pub current_value: u32,
    /// +0xac — spec +0x60, inclusive lower bound.
    pub minimum: u32,
    /// +0xb0 — spec +0x64, inclusive upper bound.
    pub maximum: u32,
}

const _: [u8; 0xb4] = [0; core::mem::size_of::<RangeView>()];
const _: [u8; 0xa4] = [0; core::mem::offset_of!(RangeView, config)];
const _: [u8; 0xa8] = [0; core::mem::offset_of!(RangeView, current_value)];
const _: [u8; 0xac] = [0; core::mem::offset_of!(RangeView, minimum)];
const _: [u8; 0xb0] = [0; core::mem::offset_of!(RangeView, maximum)];

/// range_view_construct — original: `FUN_0812b94c` @ 0x0812b94c (64 bytes:
/// 60 code ending in `ldmia sp!, {r3, r4, r5, pc}` @ 0x0812b984 plus the
/// vtable literal @ 0x0812b988; the next function begins @ 0x0812b98c).
/// Six direct `bl` call sites, all unconditional, were verified by decoding
/// every ARM B/BL word in osos.dec.
///
/// Forwards its five arguments unchanged to the ported grand-base constructor,
/// then replaces the vtable and copies the spec's four-word range tail to
/// view+0xa4..+0xb0 without validating, ordering, or clamping the values.
///
/// Deliberate deviations: Ghidra loses all five arguments and the return
/// value; raw ARM loads the stacked fifth argument, forwards it, and returns
/// the constructed `view`. The base constructor is known to return its input,
/// but this port keeps `view` rather than threading its return across host
/// pointers. The vtable is retained as its target `u32` address because no
/// dispatch through this stale image table occurs here.
///
/// # Safety
/// `view` must point to writable, 4-byte-aligned [`RangeView`], `spec` to a
/// readable [`RangeViewSpec`], and [`crate::ui::view_base::VIEW_BASE_OPS`]
/// must accept the forwarded arguments.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn range_view_construct(
    view: *mut RangeView,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const RangeViewSpec,
) -> *mut RangeView {
    view_base_construct(
        view.cast::<ViewBase>(),
        resources,
        controller,
        parent,
        core::ptr::addr_of!((*spec).base),
    );
    core::ptr::addr_of_mut!((*view).base.vtable).write_volatile(RANGE_VIEW_VTABLE_ADDRESS);
    core::ptr::addr_of_mut!((*view).config).write_volatile((*spec).base.word_58);
    core::ptr::addr_of_mut!((*view).current_value).write_volatile((*spec).initial_value);
    core::ptr::addr_of_mut!((*view).minimum).write_volatile((*spec).minimum);
    core::ptr::addr_of_mut!((*view).maximum).write_volatile((*spec).maximum);
    view
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ui::view_base::{ViewBaseOps, VIEW_BASE_OPS};
    use core::ptr;
    use parking_lot::Mutex;
    use std::boxed::Box;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LINKAGE_ARGS: (usize, usize, u32) = (0, 0, 0);
    static mut INITIALIZE_ARGS: (usize, usize, usize) = (0, 0, 0);

    unsafe extern "C" fn record_linkage_base(
        view: *mut ViewBase,
        parent: *mut u8,
        create_link: u32,
    ) -> *mut ViewBase {
        unsafe { LINKAGE_ARGS = (view as usize, parent as usize, create_link) };
        view
    }

    unsafe extern "C" fn record_initialize(
        view: *mut ViewBase,
        controller: *mut u8,
        spec: *const ViewSpec,
    ) {
        unsafe { INITIALIZE_ARGS = (view as usize, controller as usize, spec as usize) };
    }

    struct OpsGuard {
        previous: ViewBaseOps,
    }

    impl OpsGuard {
        unsafe fn install() -> Self {
            let previous = ptr::addr_of!(VIEW_BASE_OPS).read_volatile();
            ptr::addr_of_mut!(VIEW_BASE_OPS).write_volatile(ViewBaseOps {
                construct_linkage_base: record_linkage_base,
                initialize: record_initialize,
            });
            Self { previous }
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(VIEW_BASE_OPS).write_volatile(self.previous) };
        }
    }

    fn spec(config: u32, initial_value: u32, minimum: u32, maximum: u32) -> RangeViewSpec {
        RangeViewSpec {
            base: ViewSpec {
                word_00: 0,
                class_code: 0x5241_4e47,
                word_08: 0,
                word_0c: 0,
                word_10: 0,
                word_14: 0,
                flags: 1,
                geometry: [0; 0x30],
                tail: [0; 0x0c],
                word_58: config,
            },
            initial_value,
            minimum,
            maximum,
        }
    }

    #[test]
    fn layout_matches_target() {
        assert_eq!(core::mem::size_of::<RangeViewSpec>(), 0x68);
        assert_eq!(core::mem::size_of::<RangeView>(), 0xb4);
        assert_eq!(core::mem::align_of::<RangeView>(), 4);
    }

    #[test]
    fn constructs_verbatim_range_tail_after_base_chain() {
        let _lock = OPS_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        let mut view: Box<RangeView> = Box::new(unsafe { core::mem::zeroed() });
        let range_spec = spec(0, 0xffff_ffff, 9, 3);
        let mut controller = 0u8;
        let mut parent = 0u8;

        unsafe {
            LINKAGE_ARGS = (0, 0, 0);
            INITIALIZE_ARGS = (0, 0, 0);
            let this = ptr::addr_of_mut!(*view);
            let result = range_view_construct(
                this,
                ptr::null_mut(),
                ptr::addr_of_mut!(controller),
                ptr::addr_of_mut!(parent),
                &range_spec,
            );

            assert_eq!(result, this);
            assert_eq!(view.base.vtable, RANGE_VIEW_VTABLE_ADDRESS);
            assert_eq!(view.config, 0, "config copy is unconditional even when zero");
            assert_eq!(view.current_value, u32::MAX);
            assert_eq!(view.minimum, 9);
            assert_eq!(view.maximum, 3, "constructor does not reorder inverted bounds");
            assert_eq!(LINKAGE_ARGS, (this as usize, ptr::addr_of_mut!(parent) as usize, 1));
            assert_eq!(
                INITIALIZE_ARGS,
                (this as usize, ptr::addr_of_mut!(controller) as usize, ptr::addr_of!(range_spec.base) as usize)
            );
        }
    }

}
