//! `notes_value_capture_demo_mode` — `FUN_0828b3a8` @ 0x0828b3a8.
//! True extent: 64 bytes; next prologue at 0x0828b3e8 (Ghidra reports 72).
//! Raw-word scan: 0 plain / 2 predicated inbound BLs; 2 plain / 0 predicated
//! outbound BLs, one BLX through slot +0x168, and one conditional tail B.
//!
//! Obtain TCDemoMode, query its unidentified slot +0x168, and return if the
//! result is 0xffffffff. Otherwise cast owner word +0xdc to class 0x4b00;
//! on success store the result in that object's word +0x7c. Callers invoke
//! this before changing notes selection. No additional null guards are added.
//! Deliberate deviation: inline the raw-verified setter at 0x08178d98
//! (`str r1,[r0,#0x7c]; bx lr`); leave register allocation to LLVM.

use crate::app::registry::{demo_mode_instance, field_dc_as_class_4b00};

#[repr(C)]
struct DemoModeTarget {
    vtable: *const DemoModeVtable,
}

#[repr(C)]
struct DemoModeVtable {
    unresolved: [usize; 0x168 / 4],
    query: unsafe extern "C" fn(*mut DemoModeTarget) -> u32,
}

/// Owner exposes a target-width +0xdc word; an accepted object exposes +0x7c.
/// The registered demo-mode object must implement vtable slot +0x168.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn notes_value_capture_demo_mode(owner: *mut u8) {
    let demo = demo_mode_instance().cast::<DemoModeTarget>();
    let vtable = core::ptr::addr_of!((*demo).vtable).read();
    let value = ((*vtable).query)(demo);
    if value == u32::MAX {
        return;
    }
    let notes = field_dc_as_class_4b00(owner);
    if !notes.is_null() {
        notes.cast::<u32>().add(0x7c / 4).write(value);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::registry::{FrameworkObject, Registry, RegistryEntry, RegistryVtable,
        CLASS_ID_DEMO_MODE, CLASS_REGISTRY};
    use core::ptr::{addr_of, addr_of_mut};

    static mut ACCEPT: bool = true;
    static mut VALUE: u32 = 0;
    static mut CASTS: usize = 0;
    unsafe extern "C" fn cast_notes(object: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, 0x4b00);
        CASTS += 1;
        if ACCEPT { object.cast() } else { core::ptr::null_mut() }
    }
    unsafe extern "C" fn cast_demo(object: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, CLASS_ID_DEMO_MODE);
        object.cast()
    }
    unsafe extern "C" fn query(demo: *mut DemoModeTarget) -> u32 {
        assert_eq!(demo, addr_of_mut!(DEMO));
        VALUE
    }
    #[repr(C)]
    struct FixtureVtable {
        prefix: [usize; 5],
        cast: unsafe extern "C" fn(*mut FrameworkObject, u32) -> *mut u8,
        middle: [usize; 84],
        query: unsafe extern "C" fn(*mut DemoModeTarget) -> u32,
    }
    static NOTES_VTABLE: FixtureVtable = FixtureVtable {
        prefix: [0; 5], cast: cast_notes, middle: [0; 84], query,
    };
    static DEMO_VTABLE: FixtureVtable = FixtureVtable {
        prefix: [0; 5], cast: cast_demo, middle: [0; 84], query,
    };
    static mut DEMO: DemoModeTarget = DemoModeTarget {
        vtable: (&DEMO_VTABLE as *const FixtureVtable).cast(),
    };
    unsafe extern "C" fn index_of(_: *mut Registry, key: *const u32) -> i32 {
        assert_eq!(key.read(), CLASS_ID_DEMO_MODE);
        0
    }
    unsafe extern "C" fn entry_at(_: *mut Registry, index: i32, out: *mut RegistryEntry) -> *mut RegistryEntry {
        assert_eq!(index, 0);
        out.write(RegistryEntry { class_id: CLASS_ID_DEMO_MODE, instance: addr_of_mut!(DEMO).cast() });
        out
    }
    unsafe extern "C" fn unused_entry(_: *mut Registry, _: *const RegistryEntry) -> usize { panic!("unexpected insert") }
    unsafe extern "C" fn unused_assign(_: *mut Registry, _: i32, _: *const RegistryEntry) -> usize { panic!("unexpected assign") }
    unsafe extern "C" fn unused_pointer(_: *mut Registry) -> *mut u8 { panic!("unexpected notification") }
    static REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7], insert: unused_entry, unresolved_20: 0,
        assign_at: unused_assign, unresolved_28: [0; 5], entry_at,
        unresolved_40: [0; 3], index_of, unresolved_50: [0; 4],
        has_pending_changes: unused_pointer, notify_deferred: unused_pointer,
        notify_changed: unused_pointer,
    };

    #[test]
    fn sentinel_skips_owner_and_cast_failure_preserves_value_other_words_replace_it() {
        let _guard = crate::testing::CLASS_REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = crate::testing::try_map_u32_slab(crate::testing::hints::NOTES_VALUE_CAPTURE_DEMO_MODE, 0x1000) else {
            assert!(crate::testing::note_missing_u32_fixture("notes_value_capture_demo_mode"));
            return;
        };
        unsafe {
            let owner = base.cast::<u8>();
            core::ptr::write_bytes(owner, 0, 0x1000);
            let notes = owner.add(0x400);
            notes.cast::<*const FixtureVtable>().write(&NOTES_VTABLE);
            let field = owner.cast::<u32>().add(0xdc / 4);
            let value = notes.cast::<u32>().add(0x7c / 4);
            let saved_registry = addr_of!(CLASS_REGISTRY).read();
            addr_of_mut!(CLASS_REGISTRY).write(Registry {
                vtable: &REGISTRY_VTABLE, container: [0; 7], changed: 0,
                notify_enabled: 0, reserved: [0; 2], observer: core::ptr::null_mut(),
            });
            CASTS = 0;
            VALUE = u32::MAX;
            notes_value_capture_demo_mode(core::ptr::null_mut());
            assert_eq!(addr_of!(CASTS).read(), 0);
            VALUE = 42;
            notes_value_capture_demo_mode(owner); // null field
            field.write(notes as usize as u32);
            value.write(0x1234_5678);
            ACCEPT = false;
            notes_value_capture_demo_mode(owner);
            assert_eq!(value.read(), 0x1234_5678);
            ACCEPT = true;
            VALUE = u32::MAX;
            notes_value_capture_demo_mode(owner);
            assert_eq!(value.read(), 0x1234_5678);
            for word in [0, 1, 0x8000_0000, 0xffff_fffe] {
                VALUE = word;
                notes_value_capture_demo_mode(owner);
                assert_eq!(value.read(), word);
                assert_eq!(value.sub(1).read(), 0);
                assert_eq!(value.add(1).read(), 0);
            }
            addr_of_mut!(CLASS_REGISTRY).write(saved_registry);
            assert_eq!(addr_of!(CASTS).read(), 5);
        }
    }
}
