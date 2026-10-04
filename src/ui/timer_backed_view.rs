//! Timer-backed view constructor — `FUN_081dc0b8` @ `0x081dc0b8`.
//!
//! True extent: 228 bytes through `0x081dc19b` (220 instruction bytes plus
//! two literals); the next function begins at `0x081dc19c`. Raw A32 decoding
//! verifies two inbound plain BL calls, six outbound plain BL calls, and zero
//! predicated BL calls in either set. Both callers allocate 0x1f8 bytes.
//!
//! Chains the view base and pair-header constructors, installs the primary
//! and secondary vtables, constructs two eight-byte elements, initializes
//! sparse state, fills cache slot zero, constructs the embedded timer, then
//! registers the view with the current task's observable.
//! Deliberate deviations: target layout is addressed with aligned u32 words
//! and byte offsets, preserving 32-bit layout on hosts. The element constructor
//! address remains opaque data passed to the existing ADS array adapter; no
//! identity is invented. Constructor return pointers are threaded as in ARM.
//! Independent byte and word stores are grouped before the next callee; no
//! observer is called between these sparse object-state writes.

use crate::app::resource_chain::ResourceProvider;
use crate::ui::view_base::{ViewBase, ViewSpec, view_base_construct};

const VTABLE: u32 = 0x0898_e3b0;
const ELEMENT_CTOR: u32 = 0x0826_75d8;

#[inline(always)]
unsafe fn initialize_state(view: *mut u8) {
    for offset in [0xa9, 0x1ec, 0x1ed, 0x1c5, 0x168, 0x169, 0x1c4] {
        view.add(offset).write_volatile(0);
    }
    for offset in [0x164, 0x1dc, 0x1b0, 0x198, 0x19c, 0x1a0, 0x1a4,
                   0x1b4, 0x1b8, 0x1e0, 0x1e4, 0x1a8, 0x1ac, 0x1e8] {
        view.add(offset).cast::<u32>().write_volatile(0);
    }
    view.add(0x1f0).cast::<u32>().write_volatile(1);
    view.add(0x1f4).cast::<u32>().write_volatile(0x0fff_ffff);
    view.add(0xa8).write_volatile(1);
}

/// Constructs a 0x1f8-byte timer-backed view in caller-owned storage.
///
/// # Safety
/// Storage must be writable and four-byte aligned. Arguments must satisfy the
/// base constructor's contract and all installed callee operations. On hosts,
/// the view address must fit u32 for timer configuration and registration.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timer_backed_view_construct(
    view: *mut u8,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const ViewSpec,
) -> *mut u8 {
    let base = view_base_construct(view.cast::<ViewBase>(), resources, controller, parent, spec).cast::<u8>();
    base.cast::<u32>().write_volatile(VTABLE);
    base.add(0xa4).cast::<u32>().write_volatile(VTABLE + 300);
    let header = crate::cxx::pair_header::pair_header_base_construct(base.add(0xac).cast()).cast::<u8>();
    let array = crate::runtime::cpp_array_construct::cpp_array_construct(
        header.add(0x11c).cast(), ELEMENT_CTOR, 8, 2,
    ).cast::<u8>();
    let view = array.sub(0x1c8);
    initialize_state(view);
    crate::app::tbm_app_client_cache::tbm_app_client_cache_fill(0);
    crate::drivers::timer::timer_schedule_shim(view as usize as u32, view.add(0x16c), 0, 0);
    crate::app::task_context_observable_dispatch::task_context_observable_dispatch(view as usize as u32);
    view
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_initialization_preserves_members_and_padding() {
        // Nonzero poison exposes accidental whole-object clearing and byte/
        // word-width mistakes, including bytes adjoining packed state flags.
        for poison in [0x5a, 0xff] {
            let mut storage = [u32::from_ne_bytes([poison; 4]); 128];
            let bytes = unsafe { core::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), 512) };
            let mut expected = [poison; 512];
            for offset in [0xa9, 0x1ec, 0x1ed, 0x1c5, 0x168, 0x169, 0x1c4] {
                expected[offset] = 0;
            }
            for offset in [0x164, 0x1dc, 0x1b0, 0x198, 0x19c, 0x1a0, 0x1a4,
                           0x1b4, 0x1b8, 0x1e0, 0x1e4, 0x1a8, 0x1ac, 0x1e8] {
                expected[offset..offset + 4].copy_from_slice(&0u32.to_ne_bytes());
            }
            expected[0x1f0..0x1f4].copy_from_slice(&1u32.to_ne_bytes());
            expected[0x1f4..0x1f8].copy_from_slice(&0x0fff_ffffu32.to_ne_bytes());
            expected[0xa8] = 1;
            unsafe { initialize_state(bytes.as_mut_ptr()); }
            assert_eq!(bytes, expected);
        }
    }
}
