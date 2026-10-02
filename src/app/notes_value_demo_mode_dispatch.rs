//! `notes_value_demo_mode_dispatch` — `FUN_0828b81c` @ 0x0828b81c.
//! True extent: 56 bytes, next function 0x0828b854. Raw-word scan verifies
//! 2 plain / 0 predicated inbound BLs; body has 3 plain / 0 predicated BLs.
//!
//! Cast owner word +0xdc to class 0x4b00. If non-null, read its word +0x7c;
//! unless that value is 0xffffffff, obtain TCDemoMode and dispatch slot +0x184
//! with that value. Callers select notes lists; the slot's identity is unknown.
//! Deliberate deviation: inline the verified two-instruction +0x7c getter
//! (0x0829cef8), rather than introduce an unported seam. Rust leaves tail-call
//! selection to LLVM. No extra null checks or value validation are added.

use crate::app::registry::{demo_mode_instance, field_dc_as_class_4b00};

#[repr(C)]
struct DemoModeTarget {
    vtable: *const DemoModeVtable,
}

#[repr(C)]
struct DemoModeVtable {
    unresolved: [usize; 0x184 / 4],
    dispatch: unsafe extern "C" fn(*mut DemoModeTarget, u32),
}

/// Owner must expose its target-width +0xdc word; accepted objects must expose
/// +0x7c. The registered demo-mode object must implement vtable slot +0x184.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn notes_value_demo_mode_dispatch(owner: *mut u8) {
    let notes = field_dc_as_class_4b00(owner);
    if notes.is_null() {
        return;
    }
    let value = notes.cast::<u32>().add(0x7c / 4).read();
    if value == u32::MAX {
        return;
    }
    let demo = demo_mode_instance().cast::<DemoModeTarget>();
    let vtable = core::ptr::addr_of!((*demo).vtable).read();
    ((*vtable).dispatch)(demo, value);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::registry::{FrameworkObject, Registry, RegistryEntry, RegistryVtable,
        CLASS_ID_DEMO_MODE, CLASS_REGISTRY};
    use core::ptr::{addr_of, addr_of_mut};

    static mut ACCEPT: bool = true;
    static mut VALUES: std::vec::Vec<u32> = std::vec::Vec::new();
    static mut LOOKUPS: usize = 0;
    unsafe extern "C" fn cast_notes(object: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, 0x4b00);
        if ACCEPT { object.cast() } else { core::ptr::null_mut() }
    }
    unsafe extern "C" fn cast_demo(object: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, CLASS_ID_DEMO_MODE);
        object.cast()
    }
    unsafe extern "C" fn dispatch(demo: *mut DemoModeTarget, value: u32) {
        assert_eq!(demo, addr_of_mut!(DEMO));
        (*addr_of_mut!(VALUES)).push(value);
    }
    #[repr(C)]
    struct FixtureVtable {
        prefix: [usize; 5],
        cast: unsafe extern "C" fn(*mut FrameworkObject, u32) -> *mut u8,
        middle: [usize; 91],
        dispatch: unsafe extern "C" fn(*mut DemoModeTarget, u32),
    }
    static NOTES_VTABLE: FixtureVtable = FixtureVtable {
        prefix: [0; 5], cast: cast_notes, middle: [0; 91], dispatch,
    };
    static DEMO_VTABLE: FixtureVtable = FixtureVtable {
        prefix: [0; 5], cast: cast_demo, middle: [0; 91], dispatch,
    };
    static mut DEMO: DemoModeTarget = DemoModeTarget {
        vtable: (&DEMO_VTABLE as *const FixtureVtable).cast(),
    };
    unsafe extern "C" fn index_of(_: *mut Registry, key: *const u32) -> i32 {
        LOOKUPS += 1;
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
    fn rejects_null_cast_and_sentinel_but_dispatches_all_other_words() {
        let _guard = crate::testing::CLASS_REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = crate::testing::try_map_u32_slab(crate::testing::hints::NOTES_VALUE_DEMO_DISPATCH, 0x1000) else {
            assert!(crate::testing::note_missing_u32_fixture("notes_value_demo_mode_dispatch"));
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
            (*addr_of_mut!(VALUES)).clear();
            LOOKUPS = 0;
            notes_value_demo_mode_dispatch(owner); // null owner field
            field.write(notes as usize as u32);
            ACCEPT = false;
            notes_value_demo_mode_dispatch(owner); // failed class cast
            ACCEPT = true;
            value.write(u32::MAX);
            notes_value_demo_mode_dispatch(owner);
            assert_eq!(addr_of!(LOOKUPS).read(), 0);
            assert!((*addr_of!(VALUES)).is_empty());
            for word in [0, 1, 0x8000_0000, 0xffff_fffe] {
                value.write(word);
                notes_value_demo_mode_dispatch(owner);
            }
            addr_of_mut!(CLASS_REGISTRY).write(saved_registry);
            assert_eq!(addr_of!(LOOKUPS).read(), 4);
            assert_eq!(&*addr_of!(VALUES), &[0, 1, 0x8000_0000, 0xffff_fffe]);
        }
    }
}
