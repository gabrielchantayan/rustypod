//! `primary_or_demo_mode_keyed_object` — original: `FUN_0817ee34` @
//! **0x0817ee34** (92 bytes; **11 unconditional direct `bl` call sites**,
//! binary-scanned by decoding every ARM B/BL word in `osos.dec`).
//!
//! Raw ARM establishes the exact extent `0x0817ee34..0x0817ee90`: the next
//! separately entered function starts with `push {r4-r8,lr}` at `0x0817ee90`.
//! Ghidra's 92-byte extent is therefore exact, though its `void` signature
//! loses the returned object pointer.
//!
//! # Algorithm
//!
//! The controller's +0x38 primary keyed-object resolver is called first with
//! `key`. Its non-NULL result is returned unchanged. In every case a supplied
//! `used_demo_mode` byte is first cleared. On a primary miss, the function
//! obtains the ported `TCDemoMode` singleton, dispatches its vtable slot
//! `+0xec` with `key`, downcasts that result to class `0x3b80`, and sets
//! `used_demo_mode` only when that fallback cast succeeds.
//!
//! The raw function has no NULL guard for the controller, its +0x38 resolver,
//! the demo-mode singleton, or either vtable. Those framework preconditions
//! are reproduced. `FUN_081b9a68` (the primary resolver) is not ported, so
//! target builds retain its verified entry directly; host tests install the
//! sole seam. Deliberate deviation: the ARM `blx` through +0xec is a final
//! Rust call, because the cast and flag write must happen afterwards.

use crate::app::registry::{demo_mode_instance, object_cast_to_class, DemoMode, FrameworkObject};

/// Checked class required of objects returned from the demo-mode fallback.
pub const FALLBACK_KEYED_OBJECT_CLASS_ID: u32 = 0x3b80;
const PRIMARY_KEYED_OBJECT_RESOLVER_ADDRESS: usize = 0x081b_9a68;

/// Controller prefix used by [`primary_or_demo_mode_keyed_object`].
#[repr(C)]
pub struct FallbackKeyedObjectContext {
    /// +0x00..+0x37: controller state not read by this wrapper.
    pub unresolved_00: [u32; 14],
    /// +0x38: primary keyed-object resolver passed to `FUN_081b9a68`.
    pub primary_resolver: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x38] = [0; core::mem::offset_of!(FallbackKeyedObjectContext, primary_resolver)];

/// Host/target operation for the unported primary resolver.
#[derive(Clone, Copy)]
pub struct FallbackKeyedObjectOps {
    pub resolve_primary: unsafe extern "C" fn(*mut u8, u32) -> *mut u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_primary_keyed_object(
    resolver: *mut u8,
    key: u32,
) -> *mut u8 {
    let resolve: unsafe extern "C" fn(*mut u8, u32) -> *mut u8 =
        unsafe { core::mem::transmute(PRIMARY_KEYED_OBJECT_RESOLVER_ADDRESS) };
    unsafe { resolve(resolver, key) }
}


#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_primary_keyed_object(
    _resolver: *mut u8,
    _key: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// Host default before a test supplies the unported primary resolver.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_FALLBACK_KEYED_OBJECT_OPS: FallbackKeyedObjectOps = FallbackKeyedObjectOps {
    resolve_primary: missing_primary_keyed_object,
};

/// Host-side seam for unported `FUN_081b9a68`; target builds bind its retail
/// entry directly above.
#[cfg(not(target_os = "none"))]
pub static mut FALLBACK_KEYED_OBJECT_OPS: FallbackKeyedObjectOps =
    DEFAULT_FALLBACK_KEYED_OBJECT_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_primary(resolver: *mut u8, key: u32) -> *mut u8 {
    unsafe { firmware_primary_keyed_object(resolver, key) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resolve_primary(resolver: *mut u8, key: u32) -> *mut u8 {
    let resolve = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(FALLBACK_KEYED_OBJECT_OPS.resolve_primary))
    };
    unsafe { resolve(resolver, key) }
}

/// Returns the primary keyed object, or a class-`0x3b80` demo-mode fallback.
///
/// # Safety
///
/// `context` must identify a live controller whose +0x38 resolver satisfies
/// `FUN_081b9a68`'s ABI. On a primary miss, the registered `TCDemoMode` and
/// its +0xec vtable entry must be valid. `used_demo_mode`, when non-NULL, must
/// point to writable memory.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn primary_or_demo_mode_keyed_object(
    context: *mut FallbackKeyedObjectContext,
    key: u32,
    used_demo_mode: *mut u8,
) -> *mut u8 {
    let resolver = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!((*context).primary_resolver))
    };
    let primary = unsafe { resolve_primary(resolver, key) };
    if !used_demo_mode.is_null() {
        unsafe { used_demo_mode.write(0) };
    }
    if !primary.is_null() {
        return primary;
    }

    let demo_mode = unsafe { demo_mode_instance() }.cast::<DemoMode>();
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*demo_mode).vtable)) };
    let candidate = unsafe { ((*vtable).fallback_keyed_object)(demo_mode, key) };
    let fallback = unsafe {
        object_cast_to_class(candidate.cast::<FrameworkObject>(), FALLBACK_KEYED_OBJECT_CLASS_ID)
    };
    if !fallback.is_null() && !used_demo_mode.is_null() {
        unsafe { used_demo_mode.write(1) };
    }
    fallback
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::registry::{
        FrameworkObjectVtable, Registry, RegistryEntry, RegistryVtable, CLASS_ID_DEMO_MODE,
        CLASS_REGISTRY,
    };
    use core::ptr::{self, addr_of, addr_of_mut};
    use std::sync::MutexGuard;

    static mut PRIMARY_RESULT: *mut u8 = ptr::null_mut();
    static mut PRIMARY_ARGS: (usize, u32) = (0, 0);
    static mut FALLBACK_ARGS: (usize, u32) = (0, 0);
    static mut FALLBACK_RESULT: *mut FrameworkObject = ptr::null_mut();

    unsafe extern "C" fn record_primary(resolver: *mut u8, key: u32) -> *mut u8 {
        PRIMARY_ARGS = (resolver as usize, key);
        PRIMARY_RESULT
    }

    unsafe extern "C" fn demo_mode_cast(
        this: *mut FrameworkObject,
        class_id: u32,
    ) -> *mut u8 {
        if class_id == CLASS_ID_DEMO_MODE { this.cast() } else { ptr::null_mut() }
    }

    unsafe extern "C" fn accepting_fallback_cast(
        this: *mut FrameworkObject,
        class_id: u32,
    ) -> *mut u8 {
        if class_id == FALLBACK_KEYED_OBJECT_CLASS_ID { this.cast() } else { ptr::null_mut() }
    }

    unsafe extern "C" fn rejecting_fallback_cast(
        _this: *mut FrameworkObject,
        _class_id: u32,
    ) -> *mut u8 {
        ptr::null_mut()
    }

    unsafe extern "C" fn record_fallback(demo_mode: *mut DemoMode, key: u32) -> *mut FrameworkObject {
        FALLBACK_ARGS = (demo_mode as usize, key);
        FALLBACK_RESULT
    }

    unsafe extern "C" fn unused_insert(_this: *mut Registry, _entry: *const RegistryEntry) -> usize {
        unreachable!()
    }
    unsafe extern "C" fn unused_assign(
        _this: *mut Registry,
        _index: i32,
        _entry: *const RegistryEntry,
    ) -> usize {
        unreachable!()
    }
    unsafe extern "C" fn demo_entry_at(
        _this: *mut Registry,
        index: i32,
        out: *mut RegistryEntry,
    ) -> *mut RegistryEntry {
        assert_eq!(index, 0);
        out.write(RegistryEntry { class_id: CLASS_ID_DEMO_MODE, instance: addr_of_mut!(DEMO_MODE).cast() });
        out
    }
    unsafe extern "C" fn demo_index_of(_this: *mut Registry, key: *const u32) -> i32 {
        if key.read() == CLASS_ID_DEMO_MODE { 0 } else { -1 }
    }
    unsafe extern "C" fn unused_notification(_this: *mut Registry) -> *mut u8 { unreachable!() }

    static REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: unused_insert,
        unresolved_20: 0,
        assign_at: unused_assign,
        unresolved_28: [0; 5],
        entry_at: demo_entry_at,
        unresolved_40: [0; 3],
        index_of: demo_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: unused_notification,
        notify_deferred: unused_notification,
        notify_changed: unused_notification,
    };

    #[repr(C)]
    struct DemoModeFixtureVtable {
        unresolved_00: [usize; 5],
        cast_to_class: unsafe extern "C" fn(*mut FrameworkObject, u32) -> *mut u8,
        unresolved_18: [usize; 53],
        fallback_keyed_object: unsafe extern "C" fn(*mut DemoMode, u32) -> *mut FrameworkObject,
        unresolved_f0: [usize; 4],
        keyed_object: usize,
    }

    static DEMO_VTABLE: DemoModeFixtureVtable = DemoModeFixtureVtable {
        unresolved_00: [0; 5],
        cast_to_class: demo_mode_cast,
        unresolved_18: [0; 53],
        fallback_keyed_object: record_fallback,
        unresolved_f0: [0; 4],
        keyed_object: 0,
    };
    static mut DEMO_MODE: DemoMode = DemoMode {
        vtable: (&DEMO_VTABLE as *const DemoModeFixtureVtable).cast(),
        manager: [0; 11],
        keyed_registry: ptr::null_mut(),
    };

    static ACCEPTING_VTABLE: FrameworkObjectVtable = FrameworkObjectVtable {
        unresolved_00: [0; 5],
        cast_to_class: accepting_fallback_cast,
    };
    static REJECTING_VTABLE: FrameworkObjectVtable = FrameworkObjectVtable {
        unresolved_00: [0; 5],
        cast_to_class: rejecting_fallback_cast,
    };
    static mut FALLBACK_OBJECT: FrameworkObject = FrameworkObject { vtable: &ACCEPTING_VTABLE };

    fn install() -> MutexGuard<'static, ()> {
        let guard = crate::testing::CLASS_REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(PRIMARY_RESULT).write(ptr::null_mut());
            addr_of_mut!(PRIMARY_ARGS).write((0, 0));
            addr_of_mut!(FALLBACK_ARGS).write((0, 0));
            addr_of_mut!(FALLBACK_RESULT).write(addr_of_mut!(FALLBACK_OBJECT));
            addr_of_mut!(FALLBACK_OBJECT).write(FrameworkObject { vtable: &ACCEPTING_VTABLE });
            addr_of_mut!(CLASS_REGISTRY).write(Registry {
                vtable: &REGISTRY_VTABLE,
                container: [0; 7],
                changed: 0,
                notify_enabled: 0,
                reserved: [0; 2],
                observer: ptr::null_mut(),
            });
            addr_of_mut!(FALLBACK_KEYED_OBJECT_OPS).write(FallbackKeyedObjectOps {
                resolve_primary: record_primary,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(CLASS_REGISTRY).write(Registry {
                vtable: ptr::null(), container: [0; 7], changed: 0, notify_enabled: 0,
                reserved: [0; 2], observer: ptr::null_mut(),
            });
            addr_of_mut!(FALLBACK_KEYED_OBJECT_OPS).write(DEFAULT_FALLBACK_KEYED_OBJECT_OPS);
        }
        drop(guard);
    }

    fn context(resolver: *mut u8) -> FallbackKeyedObjectContext {
        FallbackKeyedObjectContext { unresolved_00: [0xa5a5_a5a5; 14], primary_resolver: resolver }
    }

    #[test]
    fn primary_hit_returns_unchanged_and_clears_the_fallback_flag() {
        let guard = install();
        let mut primary = FrameworkObject { vtable: &ACCEPTING_VTABLE };
        let mut context = context(0x5151usize as *mut u8);
        unsafe { PRIMARY_RESULT = addr_of_mut!(primary).cast() };
        let mut used_demo_mode = 0xff;

        let result = unsafe {
            primary_or_demo_mode_keyed_object(addr_of_mut!(context), 0x0dad_05a9, addr_of_mut!(used_demo_mode))
        };

        assert_eq!(result, addr_of_mut!(primary).cast());
        assert_eq!(unsafe { PRIMARY_ARGS }, (0x5151, 0x0dad_05a9));
        assert_eq!(unsafe { FALLBACK_ARGS }, (0, 0), "a primary hit must not resolve demo mode");
        assert_eq!(used_demo_mode, 0);
        restore(guard);
    }

    #[test]
    fn primary_miss_returns_accepted_demo_mode_object_and_marks_the_flag() {
        let guard = install();
        let mut context = context(0x6161usize as *mut u8);
        let mut used_demo_mode = 0xff;

        let result = unsafe {
            primary_or_demo_mode_keyed_object(addr_of_mut!(context), 0x0dad_00a1, addr_of_mut!(used_demo_mode))
        };

        assert_eq!(result, unsafe { addr_of_mut!(FALLBACK_OBJECT).cast() });
        assert_eq!(unsafe { PRIMARY_ARGS }, (0x6161, 0x0dad_00a1));
        assert_eq!(unsafe { FALLBACK_ARGS }, (unsafe { addr_of_mut!(DEMO_MODE) as usize }, 0x0dad_00a1));
        assert_eq!(used_demo_mode, 1);
        restore(guard);
    }

    #[test]
    fn rejected_demo_mode_object_returns_null_without_marking_the_flag() {
        let guard = install();
        let mut context = context(0x7171usize as *mut u8);
        let mut used_demo_mode = 0xff;
        unsafe { FALLBACK_OBJECT.vtable = &REJECTING_VTABLE };

        let result = unsafe {
            primary_or_demo_mode_keyed_object(addr_of_mut!(context), 0x0dad_0002, addr_of_mut!(used_demo_mode))
        };

        assert!(result.is_null());
        assert_eq!(used_demo_mode, 0);
        assert_eq!(unsafe { FALLBACK_ARGS }.1, 0x0dad_0002);
        restore(guard);
    }

    #[test]
    fn optional_fallback_flag_may_be_null() {
        let guard = install();
        let mut context = context(0x8181usize as *mut u8);

        let result = unsafe {
            primary_or_demo_mode_keyed_object(addr_of_mut!(context), 0x0dad_0123, ptr::null_mut())
        };

        assert_eq!(result, unsafe { addr_of_mut!(FALLBACK_OBJECT).cast() });
        assert_eq!(unsafe { FALLBACK_ARGS }.1, 0x0dad_0123);
        restore(guard);
    }
}
