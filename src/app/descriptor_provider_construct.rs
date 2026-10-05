//! Descriptor-provider constructor — FUN_081b9668 @ 0x081b9668.
//!
//! True extent: 120 bytes [0x081b9668, 0x081b96e0), comprising 116 code
//! bytes and vtable literal 0x0898c520. The next function starts with
//! cmp r0,#0 at 0x081b96e0. Raw A32 words verify three outbound plain BLs
//! (0x081b9710, 0x081e170c, 0x081d2184), zero predicated BLs.
//!
//! Construct the twelve-byte-state base, install the derived vtable, clear
//! the three-word resource reference, and retain the descriptor, fallback
//! provider and extra word. Resolve descriptor word 9 through the registry
//! unless it is zero or 0x9481; a missing instance keeps the fallback. Copy
//! the descriptor's first byte to object byte 4, then clear words 7 and 8.
//! Concrete class identity is unknown. No deliberate behavioral deviations;
//! fields remain target-width words on hosts. Tests inject dependencies into
//! the same inlined implementation instead of modifying shared global seams.

use crate::app::twelve_byte_state_derived_construct::twelve_byte_state_derived_construct;
use crate::app::registry::registry_lookup_by_id;
use crate::ui::resource_ref_clear::resource_ref_clear;

#[inline(always)]
unsafe fn construct_with(
    storage: *mut u32, fallback_provider: u32, descriptor: *const u32, extra: u32,
    base: impl FnOnce(*mut u32) -> *mut u32,
    lookup: impl FnOnce(u32) -> *mut u8,
) -> *mut u32 {
    let object = base(storage);
    object.write_volatile(0x0898_c520);
    let resource = resource_ref_clear(object.add(7));
    resource.sub(2).write_volatile(fallback_provider);
    resource.add(3).write_volatile(extra);
    resource.sub(1).write_volatile(fallback_provider);
    resource.sub(3).write_volatile(descriptor as usize as u32);
    let class_id = descriptor.add(9).read();
    if class_id != 0x9481 && class_id != 0 {
        let provider = lookup(class_id);
        if !provider.is_null() {
            object.add(6).write_volatile(provider as usize as u32);
        }
    }
    let retained_descriptor = object.add(4).read() as usize as *const u8;
    object.cast::<u8>().add(4).write_volatile(retained_descriptor.read());
    object.add(7).write_volatile(0);
    object.add(8).write_volatile(0);
    object
}

/// Initialize a descriptor-backed object in caller-provided storage.
///
/// # Safety
/// The base constructor and registry must be initialized. The base's returned
/// object must have 11 writable aligned words; descriptor must have at least
/// ten readable words and its address must fit u32. No null checks are added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn descriptor_provider_construct(
    storage: *mut u32, fallback_provider: u32, descriptor: *const u32, extra: u32,
) -> *mut u32 {
    construct_with(storage, fallback_provider, descriptor, extra,
        |p| twelve_byte_state_derived_construct(p), |id| registry_lookup_by_id(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_ids_misses_and_hits_preserve_layout_and_guards() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::DESCRIPTOR_PROVIDER_CONSTRUCT, 4096,
        ) else { return };
        unsafe {
            let descriptor = slab.cast::<u32>();
            for class_id in [0, 0x9481, 0x9480, 0x9482, u32::MAX] {
                for resolved in [0, 0x1234_5678] {
                    for tag in [0u8, 0x20, 0xff] {
                        descriptor.write(tag as u32);
                        descriptor.add(9).write(class_id);
                        let mut words = [0xa5a5_a5a5; 13];
                        let object = words.as_mut_ptr().add(1);
                        let mut calls = 0;
                        let returned = construct_with(core::ptr::null_mut(), 0x8765_4321,
                            descriptor, 0xdead_beef,
                            |_| {
                                // Model the raw base constructor's byte +4..+15 clear.
                                for i in 1..4 { object.add(i).write(0); }
                                object
                            },
                            |id| { assert_eq!(id, class_id); calls += 1; resolved as usize as *mut u8 });
                        let should_lookup = class_id != 0 && class_id != 0x9481;
                        let active = if should_lookup && resolved != 0 { resolved } else { 0x8765_4321 };
                        assert_eq!(returned, object);
                        assert_eq!(calls, usize::from(should_lookup));
                        assert_eq!(words, [0xa5a5_a5a5, 0x0898_c520, tag as u32, 0, 0,
                            descriptor as usize as u32, 0x8765_4321, active, 0, 0, 0,
                            0xdead_beef, 0xa5a5_a5a5]);
                    }
                }
            }
        }
    }
}
