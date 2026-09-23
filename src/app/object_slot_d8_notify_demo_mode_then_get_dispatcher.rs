//! `object_slot_d8_notify_demo_mode_then_get_dispatcher` — original:
//! `FUN_0812d78c` @ `0x0812d78c` (44 bytes; **3 plain and 0 predicated
//! inbound `bl` calls**, raw-binary scanned).
//!
//! # Algorithm
//!
//! Obtains the `TCDemoMode` singleton, calls `object`'s vtable slot `+0xd8`
//! with `(object, demo_mode)`, then tail-branches to the command-dispatcher
//! getter. The object class and slot identity are not recovered, so the name
//! deliberately preserves its verified offset-qualified role.
//!
//! # Deliberate deviation
//!
//! Target assembly preserves the direct singleton call, four-byte target
//! vtable lookup, `blx`, and terminal branch to the existing
//! `command_dispatcher_get_veneer`. Host builds use typed vtable fixtures
//! and a volatile terminal-getter seam because host function pointers cannot
//! occupy firmware-width slots and the real getter owns target-only state.

#[cfg(not(target_arch = "arm"))]
use crate::app::registry::demo_mode_instance;
#[cfg(not(target_arch = "arm"))]
use crate::app::singletons::command_dispatcher_get;

/// Target-width object header used by this wrapper.
#[repr(C)]
pub struct ObjectSlotD8Target {
    pub vtable: *const u32,
}

/// Host representation of the recovered object vtable entry.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ObjectSlotD8Vtable {
    /// Slots `+0x00..+0xd4` are not recovered by this wrapper.
    pub unresolved_00_d4: [usize; 54],
    /// Slot `+0xd8`: receives the object and `TCDemoMode` singleton.
    pub notify_demo_mode: unsafe extern "C" fn(*mut ObjectSlotD8Target, *mut u8),
}

/// Host seam for the terminal dispatcher getter.
#[cfg(not(target_arch = "arm"))]
pub static mut COMMAND_DISPATCHER_GET: unsafe extern "C" fn() -> *mut u8 = command_dispatcher_get;

#[cfg(not(target_arch = "arm"))]
unsafe fn dispatch_get() -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(COMMAND_DISPATCHER_GET))()
}

/// Replaces the host dispatcher getter seam and returns its previous value.
///
/// # Safety
///
/// The caller must serialize access and restore the returned value.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_command_dispatcher_get_for_test(
    getter: unsafe extern "C" fn() -> *mut u8,
) -> unsafe extern "C" fn() -> *mut u8 {
    let slot = core::ptr::addr_of_mut!(COMMAND_DISPATCHER_GET);
    let previous = core::ptr::read_volatile(slot);
    core::ptr::write_volatile(slot, getter);
    previous
}

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_slot_d8_notify_demo_mode_then_get_dispatcher(
    object: *mut ObjectSlotD8Target,
) -> *mut u8 {
    let demo_mode = demo_mode_instance();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*object).vtable))
        .cast::<ObjectSlotD8Vtable>();
    ((*vtable).notify_demo_mode)(object, demo_mode);
    dispatch_get()
}

// Keep the singleton call, virtual dispatch, and terminal branch in one ARM
// fragment: `FUN_0812d78c` returns directly from the dispatcher-get veneer.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl object_slot_d8_notify_demo_mode_then_get_dispatcher
    .type object_slot_d8_notify_demo_mode_then_get_dispatcher, %function
object_slot_d8_notify_demo_mode_then_get_dispatcher:
    push    {{r4, lr}}
    mov     r4, r0
    bl      demo_mode_instance
    mov     r1, r0
    ldr     r0, [r4]
    ldr     r2, [r0, #0xd8]
    mov     r0, r4
    blx     r2
    mov     r0, r4
    pop     {{r4, lr}}
    b       command_dispatcher_get_veneer
    .size object_slot_d8_notify_demo_mode_then_get_dispatcher, . - object_slot_d8_notify_demo_mode_then_get_dispatcher
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::registry::{
        FrameworkObject, Registry, RegistryEntry, RegistryVtable, CLASS_ID_DEMO_MODE,
        CLASS_REGISTRY,
    };
    use crate::testing::CLASS_REGISTRY_TEST_LOCK as TEST_LOCK;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::MutexGuard;

    static mut NOTIFY_CALLS: u32 = 0;
    static mut SEEN_OBJECT: *mut ObjectSlotD8Target = core::ptr::null_mut();
    static mut SEEN_DEMO_MODE: *mut u8 = core::ptr::null_mut();
    static mut DISPATCHER: u8 = 0;
    unsafe extern "C" fn dispatcher_get() -> *mut u8 { addr_of_mut!(DISPATCHER) }


    unsafe extern "C" fn record_notify(object: *mut ObjectSlotD8Target, demo_mode: *mut u8) {
        NOTIFY_CALLS += 1;
        SEEN_OBJECT = object;
        SEEN_DEMO_MODE = demo_mode;
    }

    unsafe extern "C" fn index_of(_registry: *mut Registry, key: *const u32) -> i32 {
        (key.read() == CLASS_ID_DEMO_MODE) as i32 - 1
    }
    unsafe extern "C" fn entry_at(_registry: *mut Registry, index: i32, out: *mut RegistryEntry) -> *mut RegistryEntry {
        if index == 0 {
            out.write(RegistryEntry { class_id: CLASS_ID_DEMO_MODE, instance: addr_of_mut!(DEMO_MODE).cast() });
            out
        } else {
            core::ptr::null_mut()
        }
    }
    unsafe extern "C" fn cast_demo_mode(object: *mut FrameworkObject, class_id: u32) -> *mut u8 {
        if class_id == CLASS_ID_DEMO_MODE { object.cast() } else { core::ptr::null_mut() }
    }
    unsafe extern "C" fn unused_entry(_registry: *mut Registry, _entry: *const RegistryEntry) -> usize { 0 }
    unsafe extern "C" fn unused_assign(_registry: *mut Registry, _index: i32, _entry: *const RegistryEntry) -> usize { 0 }
    unsafe extern "C" fn unused_pointer(_registry: *mut Registry) -> *mut u8 { core::ptr::null_mut() }

    static REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7], insert: unused_entry, unresolved_20: 0,
        assign_at: unused_assign, unresolved_28: [0; 5], entry_at,
        unresolved_40: [0; 3], index_of, unresolved_50: [0; 4],
        has_pending_changes: unused_pointer, notify_deferred: unused_pointer,
        notify_changed: unused_pointer,
    };
    #[repr(C)]
    struct DemoModeFixtureVtable {
        unresolved_00_10: [usize; 5],
        cast_to_class: unsafe extern "C" fn(*mut FrameworkObject, u32) -> *mut u8,
    }
    static DEMO_MODE_VTABLE: DemoModeFixtureVtable = DemoModeFixtureVtable {
        unresolved_00_10: [0; 5], cast_to_class: cast_demo_mode,
    };
    static mut DEMO_MODE: ObjectSlotD8Target = ObjectSlotD8Target {
        vtable: (&DEMO_MODE_VTABLE as *const DemoModeFixtureVtable).cast(),
    };
    static OBJECT_VTABLE: ObjectSlotD8Vtable = ObjectSlotD8Vtable {
        unresolved_00_d4: [0; 54], notify_demo_mode: record_notify,
    };
    static mut OBJECT: ObjectSlotD8Target = ObjectSlotD8Target {
        vtable: (&OBJECT_VTABLE as *const ObjectSlotD8Vtable).cast(),
    };

    fn install_demo_mode() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(NOTIFY_CALLS).write(0);
            addr_of_mut!(SEEN_OBJECT).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_DEMO_MODE).write(core::ptr::null_mut());
            addr_of_mut!(CLASS_REGISTRY).write(Registry {
                vtable: &REGISTRY_VTABLE, container: [0; 7], changed: 0,
                notify_enabled: 0, reserved: [0; 2], observer: core::ptr::null_mut(),
            });
        }
        guard
    }

    #[test]
    fn notifies_slot_d8_with_the_demo_mode_singleton() {
        let _guard = install_demo_mode();
        let _dispatcher_guard = crate::testing::OBJECT_SLOT_D8_NOTIFY_TEST_LOCK
            .lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { set_command_dispatcher_get_for_test(dispatcher_get) };
        unsafe {
            let dispatcher = object_slot_d8_notify_demo_mode_then_get_dispatcher(addr_of_mut!(OBJECT));
            assert_eq!(dispatcher, addr_of_mut!(DISPATCHER));
            set_command_dispatcher_get_for_test(previous);
            assert_eq!(addr_of!(NOTIFY_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_OBJECT).read(), addr_of_mut!(OBJECT));
            assert_eq!(addr_of!(SEEN_DEMO_MODE).read(), addr_of_mut!(DEMO_MODE).cast());
        }
    }
}
