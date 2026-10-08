//! Tick-input view constructor — FUN_0811a44c @ 0x0811a44c.
//! True extent [0x0811a44c,0x0811a4b8): 100 code bytes plus two literals.
//! Raw whole-image word decoding verifies two incoming plain BLs
//! (0x0811a044, 0x081b9ed8), four outgoing plain BLs, no predicated BLs.
//! Chains to ViewBase, installs vtable 0x08981ae4, clears state words
//! +0xa4/+0xa8/+0xb0, allocates a 52-byte tick accumulator (divisor 5,
//! mode 1, backoff 350 ms), stores it at +0xac, sets its scale limit to
//! 16, and clears byte +0xb8. All other tail bytes remain untouched.
//! Deliberate deviations: restore the five arguments and object return
//! omitted by Ghidra; discard the stale outgoing spec stack slot at the
//! verified four-argument accumulator call. Target pointer words stay u32.
//! Both callers allocate 0xbc bytes; no more specific widget identity is
//! established, so the name describes its verified tick-input role.

use crate::app::resource_chain::ResourceProvider;
use crate::app::tick_accumulator::{TickAccumulator, tick_accumulator_construct,
    tick_accumulator_set_scale_factor_limit};
use crate::ui::view_base::{ViewBase, ViewSpec, view_base_construct};
use core::ptr::addr_of_mut;

/// RetailOS layout, including the untouched word and trailing padding.
#[repr(C)]
pub struct TickInputView {
    pub base: ViewBase,
    pub state_a4: u32,
    pub state_a8: u32,
    pub accumulator: u32,
    pub state_b0: u32,
    pub untouched_b4: u32,
    pub active: u8,
    pub padding: [u8; 3],
}

const _: [u8; 0xbc] = [0; core::mem::size_of::<TickInputView>()];

/// # Safety
/// Objects must be aligned and valid for their types. Base, allocator and
/// tick dependencies must be configured. Allocation failure is not guarded,
/// matching the original constructor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tick_input_view_construct(
    view: *mut TickInputView,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const ViewSpec,
) -> *mut TickInputView {
    let view = view_base_construct(
        view.cast(), resources, controller, parent, spec,
    ).cast::<TickInputView>();
    initialize_state(view);
    let storage = crate::heap::veneers::operator_new(0x34).cast::<TickAccumulator>();
    let accumulator = tick_accumulator_construct(storage, 5, 1, 350);
    addr_of_mut!((*view).accumulator).write_volatile(accumulator as usize as u32);
    tick_accumulator_set_scale_factor_limit(accumulator, 16);
    addr_of_mut!((*view).active).write_volatile(0);
    view
}

#[inline(always)]
unsafe fn initialize_state(view: *mut TickInputView) {
    addr_of_mut!((*view).base.vtable).write_volatile(0x0898_1ae4);
    addr_of_mut!((*view).state_a4).write_volatile(0);
    addr_of_mut!((*view).state_a8).write_volatile(0);
    addr_of_mut!((*view).state_b0).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_owned_initial_state_before_allocation() {
        for sentinel in [0u8, 0x5a, 0xff] {
            let mut view = core::mem::MaybeUninit::<TickInputView>::uninit();
            unsafe {
                let bytes = view.as_mut_ptr().cast::<u8>();
                core::ptr::write_bytes(bytes, sentinel, 0xbc);
                initialize_state(view.as_mut_ptr());
                // Independent byte-level reference checks every untouched
                // byte, including the pending pointer and byte flag.
                let actual = core::slice::from_raw_parts(bytes, 0xbc);
                for offset in 0..0xbc {
                    let expected = if offset < 4 {
                        0x0898_1ae4u32.to_le_bytes()[offset]
                    } else if (0xa4..0xac).contains(&offset) || (0xb0..0xb4).contains(&offset) {
                        0
                    } else {
                        sentinel
                    };
                    assert_eq!(actual[offset], expected, "offset {offset:#x}");
                }
            }
        }
    }
}
