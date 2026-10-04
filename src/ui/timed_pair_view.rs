//! Timed pair-header view constructor — `FUN_081da564` @ `0x081da564`.
//!
//! True extent: 116 bytes (112 instruction bytes and the vtable literal at
//! 0x081da5d4); the next function starts at 0x081da5d8. Full-image raw A32
//! decoding verifies 2 inbound plain BL calls and 0 predicated BL calls;
//! the body has 3 plain BL calls and 0 predicated BL calls.
//!
//! Constructs the inherited ViewPairHeader, installs vtable 0x0898e1cc,
//! clears sparse state, copies the delay and paired initial values from
//! spec+0x58/+0x5c, zero-extends spec's halfword at +0x60, and sets the
//! enabled byte. Constructs the embedded timer at +0x17c with the view as
//! config, then stops it and sets its delay (does not arm it). Returns view.
//! Deliberate deviations: aligned word/halfword accesses and byte offsets
//! preserve target layout on hosts. The meaning of the paired value and
//! halfword beyond their initialization is not inferred.

use crate::app::resource_chain::ResourceProvider;
use crate::drivers::timer::{timer_schedule_shim, timer_start_after};
use crate::ui::view_base::{ViewPairHeader, ViewSpec, view_pair_header_construct};

#[inline(always)]
unsafe fn initialize_state(view: *mut u8, spec: *const u8) {
    view.cast::<u32>().write(0x0898_e1cc);
    view.add(0x164).cast::<u32>().write(0);
    view.add(0x178).cast::<u32>().write(spec.add(0x58).cast::<u32>().read());
    let initial_value = spec.add(0x5c).cast::<u32>().read();
    view.add(0x168).cast::<u32>().write(initial_value);
    view.add(0x16c).cast::<u32>().write(initial_value);
    view.add(0x170).cast::<u32>().write(spec.add(0x60).cast::<u16>().read() as u32);
    view.add(0x1a8).cast::<u32>().write(0);
    view.add(0x174).write(1);
}

/// Constructs a 0x1ac-byte timed pair-header view in caller-owned storage.
///
/// # Safety
/// `view` must be writable and four-byte aligned for 0x1ac bytes; `spec`
/// must be four-byte aligned and readable through +0x61, and satisfy the
/// inherited ViewSpec contract. Remaining arguments and installed operations
/// must satisfy the base and timer constructors. The view address must fit
/// u32 for the timer's config word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timed_pair_view_construct(
    view: *mut u8,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const ViewSpec,
) -> *mut u8 {
    let view = view_pair_header_construct(
        view.cast::<ViewPairHeader>(), resources, controller, parent, spec,
    ).cast::<u8>();
    initialize_state(view, spec.cast());
    timer_schedule_shim(view as usize as u32, view.add(0x17c), 0, 0);
    timer_start_after(view.add(0x17c), view.add(0x178).cast::<u32>().read());
    view
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_preserves_padding_and_zero_extends_halfword() {
        for (delay, value, halfword) in [(0, 0, 0u16), (u32::MAX, 0x8123_4567, 0xffff), (1, u32::MAX, 0x8000)] {
            let mut storage = [0xa5a5_a5a5u32; 0x1ac / 4];
            let mut spec = [0xffff_ffffu32; 0x64 / 4];
            spec[0x58 / 4] = delay;
            spec[0x5c / 4] = value;
            spec[0x60 / 4] = 0xffff_0000 | halfword as u32;
            let mut expected = [0xa5u8; 0x1ac];
            for (offset, word) in [(0, 0x0898_e1cc), (0x164, 0), (0x178, delay),
                                   (0x168, value), (0x16c, value), (0x170, halfword as u32), (0x1a8, 0)] {
                expected[offset..offset + 4].copy_from_slice(&word.to_ne_bytes());
            }
            expected[0x174] = 1;
            unsafe {
                initialize_state(storage.as_mut_ptr().cast(), spec.as_ptr().cast());
                let actual = core::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), 0x1ac);
                assert_eq!(actual, expected);
            }
        }
    }
}
