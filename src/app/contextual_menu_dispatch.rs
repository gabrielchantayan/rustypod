//! `contextual_menu_dispatch` — `FUN_08219d64` @ 0x08219d64.
//! True extent: 80 bytes, ending before the prologue at 0x08219db4.
//! Raw-word scan: 0 plain / 2 predicated inbound BLs; 1 plain / 0
//! predicated outbound BLs, 2 BLX calls, and a final virtual tail BX.
//!
//! HandleShowContextualMenu callers obtain TCDemoMode's slot +0x168 value.
//! Return zero for 0xffffffff without touching the owner. Otherwise pass
//! the value to owner slot +0x130, reload the owner's vtable, and pass that
//! result to slot +0x148, returning its result. Slot identities are unknown.
//! Deliberate deviations: LLVM selects registers and call/tail-call lowering;
//! host vtables use pointer-sized entries with the same target word indices.

use crate::app::registry::demo_mode_instance;

#[repr(C)]
struct DemoTarget {
    vtable: *const DemoVtable,
}
#[repr(C)]
struct DemoVtable {
    unresolved: [usize; 0x168 / 4],
    query: unsafe extern "C" fn(*mut DemoTarget) -> u32,
}

#[repr(C)]
pub struct ContextualMenuTarget {
    vtable: *const ContextualMenuVtable,
}
#[repr(C)]
struct ContextualMenuVtable {
    unresolved: [usize; 0x130 / 4],
    slot_130: unsafe extern "C" fn(*mut ContextualMenuTarget, u32) -> u32,
    middle: [usize; (0x148 - 0x134) / 4],
    slot_148: unsafe extern "C" fn(*mut ContextualMenuTarget, u32) -> u32,
}

/// # Safety
/// The registered demo object and owner must implement their indicated slots.
/// The owner may be null only when the demo query returns the sentinel.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn contextual_menu_dispatch(owner: *mut ContextualMenuTarget) -> u32 {
    let demo = demo_mode_instance().cast::<DemoTarget>();
    let demo_vtable = core::ptr::addr_of!((*demo).vtable).read();
    let value = ((*demo_vtable).query)(demo);
    if value == u32::MAX {
        return 0;
    }
    let vtable = core::ptr::addr_of!((*owner).vtable).read();
    let resolved = ((*vtable).slot_130)(owner, value);
    let vtable = core::ptr::addr_of!((*owner).vtable).read();
    ((*vtable).slot_148)(owner, resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::registry::{FrameworkObject, Registry, RegistryEntry, RegistryVtable,
        CLASS_ID_DEMO_MODE, CLASS_REGISTRY};
    use core::ptr::{addr_of, addr_of_mut};

    static mut VALUE: u32 = 0;
    static mut STAGE: u32 = 0;
    #[repr(C)]
    struct FixtureDemoVtable {
        prefix: [usize; 5],
        cast: unsafe extern "C" fn(*mut FrameworkObject, u32) -> *mut u8,
        middle: [usize; 84],
        query: unsafe extern "C" fn(*mut DemoTarget) -> u32,
    }
    unsafe extern "C" fn cast(object: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, CLASS_ID_DEMO_MODE);
        object.cast()
    }
    unsafe extern "C" fn query(demo: *mut DemoTarget) -> u32 {
        assert_eq!(demo, addr_of_mut!(DEMO));
        assert_eq!(addr_of!(STAGE).read(), 0);
        STAGE = 1;
        VALUE
    }
    static DEMO_VTABLE: FixtureDemoVtable = FixtureDemoVtable {
        prefix: [0; 5], cast, middle: [0; 84], query,
    };
    static mut DEMO: DemoTarget = DemoTarget {
        vtable: (&DEMO_VTABLE as *const FixtureDemoVtable).cast(),
    };
    unsafe extern "C" fn resolve(owner: *mut ContextualMenuTarget, value: u32) -> u32 {
        assert_eq!(addr_of!(STAGE).read(), 1);
        assert_eq!(value, addr_of!(VALUE).read());
        STAGE = 2;
        (*owner).vtable = &REPLACEMENT;
        value.rotate_left(7) ^ 0x1234_5678
    }
    unsafe extern "C" fn stale(_: *mut ContextualMenuTarget, _: u32) -> u32 {
        panic!("dispatch must reload the vtable after resolution")
    }
    unsafe extern "C" fn dispatch(owner: *mut ContextualMenuTarget, resolved: u32) -> u32 {
        assert_eq!((*owner).vtable, &REPLACEMENT as *const ContextualMenuVtable);
        assert_eq!(addr_of!(STAGE).read(), 2);
        assert_eq!(resolved, VALUE.rotate_left(7) ^ 0x1234_5678);
        STAGE = 3;
        resolved.wrapping_add(0x89ab_cdef)
    }
    static INITIAL: ContextualMenuVtable = ContextualMenuVtable {
        unresolved: [0; 76], slot_130: resolve, middle: [0; 5], slot_148: stale,
    };
    static REPLACEMENT: ContextualMenuVtable = ContextualMenuVtable {
        unresolved: [0; 76], slot_130: resolve, middle: [0; 5], slot_148: dispatch,
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
    fn sentinel_skips_owner_and_other_words_resolve_with_reloaded_vtable() {
        let _guard = crate::testing::CLASS_REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = addr_of!(CLASS_REGISTRY).read();
            addr_of_mut!(CLASS_REGISTRY).write(Registry {
                vtable: &REGISTRY_VTABLE, container: [0; 7], changed: 0,
                notify_enabled: 0, reserved: [0; 2], observer: core::ptr::null_mut(),
            });
            VALUE = u32::MAX;
            STAGE = 0;
            assert_eq!(contextual_menu_dispatch(core::ptr::null_mut()), 0);
            assert_eq!(addr_of!(STAGE).read(), 1);
            for value in [0u32, 1, 0x8000_0000, 0xffff_fffe] {
                VALUE = value;
                STAGE = 0;
                let mut owner = ContextualMenuTarget { vtable: &INITIAL };
                let result = contextual_menu_dispatch(&mut owner);
                assert_eq!(result, (value.rotate_left(7) ^ 0x1234_5678).wrapping_add(0x89ab_cdef));
                assert_eq!(addr_of!(STAGE).read(), 3);
            }
            addr_of_mut!(CLASS_REGISTRY).write(saved);
        }
    }
}
