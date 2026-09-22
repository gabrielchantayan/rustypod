//! `demo_mode_slot_18c_dispatch` — original: `FUN_08292ce8` @
//! `0x08292ce8` (32 bytes; 2 plain and 1 predicated inbound `bl` calls).
//!
//! # Algorithm
//!
//! Saves the supplied argument, obtains the `TCDemoMode` singleton through
//! [`crate::app::registry::demo_mode_instance`], then tail-dispatches its
//! vtable entry at `+0x18c`, passing the singleton in `r0` and the saved
//! argument in `r1`. The slot's identity is not recovered; its caller-visible
//! role is therefore retained as an offset-qualified dispatch.
//!
//! # Deliberate deviation
//!
//! Target assembly preserves the original direct `bl`, target-width vtable
//! lookup, and terminal `bx`. Host builds use a typed vtable fixture because
//! host function pointers cannot occupy the firmware's four-byte vtable slot.

#[cfg(not(target_arch = "arm"))]
use crate::app::registry::demo_mode_instance;

/// Target-width `TCDemoMode` object header used by this dispatch.
#[repr(C)]
pub struct DemoModeSlot18cTarget {
    pub vtable: *const u32,
}

/// Host representation of the one recovered `TCDemoMode` vtable entry.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct DemoModeSlot18cVtable {
    /// Slots `+0x00..+0x188` are not recovered by this wrapper.
    pub unresolved_00_188: [usize; 99],
    /// Slot `+0x18c`: receives the singleton and forwarded argument.
    pub dispatch: unsafe extern "C" fn(*mut DemoModeSlot18cTarget, u32),
}

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn demo_mode_slot_18c_dispatch(argument: u32) {
    let demo_mode = demo_mode_instance().cast::<DemoModeSlot18cTarget>();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*demo_mode).vtable))
        .cast::<DemoModeSlot18cVtable>();
    ((*vtable).dispatch)(demo_mode, argument);
}

// Keep the singleton call and tail virtual dispatch in one ARM fragment: the
// original returns directly from the vtable target rather than this wrapper.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl demo_mode_slot_18c_dispatch
    .type demo_mode_slot_18c_dispatch, %function
demo_mode_slot_18c_dispatch:
    push    {{r4, lr}}
    mov     r4, r0
    bl      demo_mode_instance
    ldr     r1, [r0]
    ldr     r2, [r1, #0x18c]
    mov     r1, r4
    pop     {{r4, lr}}
    bx      r2
    .size demo_mode_slot_18c_dispatch, . - demo_mode_slot_18c_dispatch
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
    use core::ptr::{addr_of, addr_of_mut};
    use crate::testing::CLASS_REGISTRY_TEST_LOCK as TEST_LOCK;
    use std::sync::MutexGuard;

    static mut DISPATCH_CALLS: u32 = 0;
    static mut SEEN_DEMO_MODE: *mut DemoModeSlot18cTarget = core::ptr::null_mut();
    static mut SEEN_ARGUMENT: u32 = 0;

    unsafe extern "C" fn record_dispatch(demo_mode: *mut DemoModeSlot18cTarget, argument: u32) {
        DISPATCH_CALLS += 1;
        SEEN_DEMO_MODE = demo_mode;
        SEEN_ARGUMENT = argument;
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
        unresolved_18_188: [usize; 93],
        dispatch: unsafe extern "C" fn(*mut DemoModeSlot18cTarget, u32),
    }

    static VTABLE: DemoModeFixtureVtable = DemoModeFixtureVtable {
        unresolved_00_10: [0; 5],
        cast_to_class: cast_demo_mode,
        unresolved_18_188: [0; 93],
        dispatch: record_dispatch,
    };
    static mut DEMO_MODE: DemoModeSlot18cTarget = DemoModeSlot18cTarget {
        vtable: (&VTABLE as *const DemoModeFixtureVtable).cast(),
    };

    fn install_demo_mode() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(DISPATCH_CALLS).write(0);
            addr_of_mut!(SEEN_DEMO_MODE).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_ARGUMENT).write(0);
            addr_of_mut!(DEMO_MODE).write(DemoModeSlot18cTarget {
                vtable: (&VTABLE as *const DemoModeFixtureVtable).cast(),
            });
            addr_of_mut!(CLASS_REGISTRY).write(Registry {
                vtable: &REGISTRY_VTABLE, container: [0; 7], changed: 0,
                notify_enabled: 0, reserved: [0; 2], observer: core::ptr::null_mut(),
            });
        }
        guard
    }

    #[test]
    fn forwards_singleton_and_argument_to_slot_18c() {
        let _guard = install_demo_mode();
        unsafe {
            demo_mode_slot_18c_dispatch(0xa5a5_5a5a);
            assert_eq!(addr_of!(DISPATCH_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_DEMO_MODE).read(), addr_of_mut!(DEMO_MODE));
            assert_eq!(addr_of!(SEEN_ARGUMENT).read(), 0xa5a5_5a5a);
        }
    }
}
