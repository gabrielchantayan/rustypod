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

/// Specification for the configured range-view layer. The ten-word tail
/// occupies +0x68..+0x8f; the constructor deliberately ignores word +0x88.
#[repr(C)]
pub struct ConfiguredRangeViewSpec {
    pub range: RangeViewSpec,
    pub configuration: [u32; 10],
}

#[repr(C)]
pub struct RangeConfigurationSlot {
    pub configuration: u32,
    pub state: u32,
}

/// Eight configuration/state pairs and one final configuration word.
#[repr(C)]
pub struct ConfiguredRangeView {
    pub range: RangeView,
    pub state: u32,
    pub slots: [RangeConfigurationSlot; 8],
    pub final_configuration: u32,
}

const _: [u8; 0x90] = [0; core::mem::size_of::<ConfiguredRangeViewSpec>()];
const _: [u8; 0xfc] = [0; core::mem::size_of::<ConfiguredRangeView>()];
const _: [u8; 0xb8] = [0; core::mem::offset_of!(ConfiguredRangeView, slots)];

/// configured_range_view_construct — original: FUN_0820fa58 @ 0x0820fa58.
/// True extent 144 bytes: 140 code bytes through the pop at 0x0820fae0,
/// then vtable literal 0x08992750 at 0x0820fae4. The next real function
/// starts at 0x0820fae8. Raw word decoding finds two incoming plain BLs
/// (0x081e0114, 0x0821355c), zero predicated BLs, and one outgoing plain
/// BL to range_view_construct at 0x0820fa64.
///
/// Forward all five arguments to the range base, replace its vtable, clear
/// +0xb4, and copy spec +0x6c/+0x68/+0x70..+0x84 to the eight alternating
/// configuration words at +0xb8..+0xf0. Copy +0x8c to +0xf8, then clear
/// each paired state word. Spec +0x88 is unused; no range clamping occurs.
///
/// Deliberate deviations: restore the arguments and pointer return lost by
/// Ghidra. Keep the original view pointer across the base call, whose return
/// is verified identical. Store the vtable as a target u32, without host
/// dispatch. Unknown configuration meanings remain positional, not guessed.
///
/// # Safety
/// Both pointers must reference aligned, valid objects of their stated types;
/// VIEW_BASE_OPS must accept the forwarded base-construction arguments.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn configured_range_view_construct(
    view: *mut ConfiguredRangeView,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const ConfiguredRangeViewSpec,
) -> *mut ConfiguredRangeView {
    range_view_construct(
        core::ptr::addr_of_mut!((*view).range), resources, controller, parent,
        core::ptr::addr_of!((*spec).range),
    );
    core::ptr::addr_of_mut!((*view).range.base.vtable).write_volatile(0x0899_2750);
    core::ptr::addr_of_mut!((*view).state).write_volatile(0);
    for (slot, source) in [1usize, 0, 2, 3, 4, 5, 6, 7].into_iter().enumerate() {
        core::ptr::addr_of_mut!((*view).slots[slot].configuration)
            .write_volatile((*spec).configuration[source]);
    }
    // The first paired clear precedes the last configuration store in stock.
    core::ptr::addr_of_mut!((*view).slots[0].state).write_volatile(0);
    core::ptr::addr_of_mut!((*view).final_configuration)
        .write_volatile((*spec).configuration[9]);
    for slot in 1..8 {
        core::ptr::addr_of_mut!((*view).slots[slot].state).write_volatile(0);
    }
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

    #[test]
    fn configured_tail_swaps_first_words_skips_reserved_and_clears_dirty_state() {
        let _lock = OPS_LOCK.lock();
        let _ops = unsafe { OpsGuard::install() };
        for configuration in [
            [0, u32::MAX, 2, 3, 4, 5, 6, 7, 0x8888_8888, 9],
            [u32::MAX, 0, 0x8000_0000, 0, u32::MAX, 5, 6, 7, 0, u32::MAX],
        ] {
            let specification = ConfiguredRangeViewSpec {
                range: spec(0, u32::MAX, 9, 3),
                configuration,
            };
            // All fields are integers/byte arrays, so poison is a valid value.
            let mut storage = core::mem::MaybeUninit::<ConfiguredRangeView>::uninit();
            unsafe {
                ptr::write_bytes(storage.as_mut_ptr().cast::<u8>(), 0xa5, 0xfc);
                let view = storage.as_mut_ptr();
                let returned = configured_range_view_construct(
                    view, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), &specification,
                );
                assert_eq!(returned, view);
                assert_eq!((*view).range.base.vtable, 0x0899_2750);
                assert_eq!((*view).range.current_value, u32::MAX);
                assert_eq!(((*view).range.minimum, (*view).range.maximum), (9, 3));
                assert_eq!((*view).state, 0);
                let words = core::slice::from_raw_parts(view.cast::<u32>().add(0xb4 / 4), 18);
                assert_eq!(words, &[
                    0, configuration[1], 0, configuration[0], 0, configuration[2], 0,
                    configuration[3], 0, configuration[4], 0, configuration[5], 0,
                    configuration[6], 0, configuration[7], 0, configuration[9],
                ]);
            }
        }
    }

}
