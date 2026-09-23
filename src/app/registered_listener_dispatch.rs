//! `registered_listener_dispatch` — original: `FUN_0812d628` @ `0x0812d628`.
//!
//! **148 bytes** (`0x0812d628..0x0812d6bb`); the literal global pointer at
//! `0x0812d6bc` is not code, and `0x0812d6c0` begins the next real function.
//! Raw `osos.dec` has three inbound plain direct `bl` sites (`0x08126688`,
//! `0x081b13ac`, and `0x0828a1f8`) and no predicated direct `bl` sites. The
//! body has one unconditional plain direct `bl` to `registered_listener_notify`,
//! two unconditional indirect `blx` sites, and one predicated indirect `blxne`
//! site.
//!
//! Algorithm: retrieve the global registry, enumerate its initial count through
//! vtable slot `+0x3c`, take each enumerated entry's handler from `+0x98`, test
//! handler vtable slot `+0x2c`, and when nonzero call slot `+0x1c` with the
//! event and a zero-initialized output word. Add that output word to the return
//! from `registered_listener_notify(event)`.
//!
//! Deliberate deviation: the global registry and all three observed virtual
//! methods remain unported. Target builds access their verified addresses and
//! slots; host builds use typed seams without assigning them unverified names.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

use super::registered_listener_notify::registered_listener_notify;

const RETAIL_REGISTRY_POINTER: *mut *mut u8 = 0x089c_c8dc as *mut *mut u8;
const ENTRY_HANDLER_OFFSET: usize = 0x98;

#[derive(Clone, Copy)]
pub struct RegisteredListenerDispatchOps {
    pub registry_get: unsafe extern "C" fn() -> *mut u8,
    pub entry_at: unsafe extern "C" fn(*mut u8, u32, *mut *mut u8),
    pub handler_is_active: unsafe extern "C" fn(*mut u8) -> u32,
    pub handler_dispatch: unsafe extern "C" fn(*mut u8, u32, *mut u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_registry_get() -> *mut u8 {
    panic!("install registered-listener dispatch host operations before calling")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_entry_at(_registry: *mut u8, _index: u32, _entry_out: *mut *mut u8) {
    panic!("install registered-listener dispatch host operations before calling")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handler_is_active(_handler: *mut u8) -> u32 {
    panic!("install registered-listener dispatch host operations before calling")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handler_dispatch(_handler: *mut u8, _event: u32, _output: *mut u32) {
    panic!("install registered-listener dispatch host operations before calling")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_REGISTERED_LISTENER_DISPATCH_OPS: RegisteredListenerDispatchOps = RegisteredListenerDispatchOps {
    registry_get: missing_registry_get,
    entry_at: missing_entry_at,
    handler_is_active: missing_handler_is_active,
    handler_dispatch: missing_handler_dispatch,
};

#[cfg(not(target_os = "none"))]
pub static mut REGISTERED_LISTENER_DISPATCH_OPS: RegisteredListenerDispatchOps =
    DEFAULT_REGISTERED_LISTENER_DISPATCH_OPS;
/// Dispatches an event through every active handler in the global registry.
///
/// # Safety
///
/// Target callers require a valid registry and handler object graph. Host callers
/// must install [`REGISTERED_LISTENER_DISPATCH_OPS`] and provide entries with a
/// target-width handler word at offset `+0x98`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_listener_dispatch(_owner: *mut u8, event: u32, entry: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        type EntryAt = unsafe extern "C" fn(*mut u8, u32, *mut *mut u8);
        type HandlerIsActive = unsafe extern "C" fn(*mut u8) -> u32;
        type HandlerDispatch = unsafe extern "C" fn(*mut u8, u32, *mut u32);
        let mut entry = entry;

        let registry = unsafe { RETAIL_REGISTRY_POINTER.read_volatile() };
        let count = unsafe { registry.add(4).cast::<u32>().read() };
        let mut output = 0;
        for index in 0..count {
            let vtable = unsafe { registry.cast::<*const u8>().read_volatile() };
            let entry_at: EntryAt = unsafe { vtable.add(0x3c).cast::<EntryAt>().read_volatile() };
            unsafe { entry_at(registry, index, &mut entry) };
            let handler = unsafe { entry.add(ENTRY_HANDLER_OFFSET).cast::<*mut u8>().read() };
            let vtable = unsafe { handler.cast::<*const u8>().read_volatile() };
            let handler_is_active: HandlerIsActive = unsafe { vtable.add(0x2c).cast::<HandlerIsActive>().read_volatile() };
            if unsafe { handler_is_active(handler) } != 0 {
                let vtable = unsafe { handler.cast::<*const u8>().read_volatile() };
                let handler_dispatch: HandlerDispatch = unsafe { vtable.add(0x1c).cast::<HandlerDispatch>().read_volatile() };
                unsafe { handler_dispatch(handler, event, &mut output) };
            }
        }
        unsafe { registered_listener_notify(event) }.wrapping_add(output)
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { core::ptr::read_volatile(addr_of!(REGISTERED_LISTENER_DISPATCH_OPS)) };
        let registry = unsafe { (ops.registry_get)() };
        let count = unsafe { registry.add(4).cast::<u32>().read() };
        let mut output = 0;
        let mut entry = entry;
        for index in 0..count {
            unsafe { (ops.entry_at)(registry, index, &mut entry) };
            let handler = unsafe { entry.add(ENTRY_HANDLER_OFFSET).cast::<u32>().read() as usize as *mut u8 };
            if unsafe { (ops.handler_is_active)(handler) } != 0 {
                unsafe { (ops.handler_dispatch)(handler, event, &mut output) };
            }
        }
        unsafe { registered_listener_notify(event) }.wrapping_add(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::registered_listener_notify::{RegisteredListenerNotifyOps, REGISTERED_LISTENER_NOTIFY_OPS};
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut REGISTRY: [u32; 2] = [0; 2];
    static mut ENTRIES: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut ACTIVE: [u32; 3] = [0; 3];
    static mut DISPATCH_ORDER: [u32; 3] = [0; 3];
    static mut DISPATCH_LEN: usize = 0;
    static mut NOTIFY_COLLECTION: [u32; 2] = [0, 1];
    static mut NOTIFY_LISTENER: *mut u8 = 7usize as *mut u8;

    unsafe extern "C" fn registry_get() -> *mut u8 { core::ptr::addr_of_mut!(REGISTRY).cast() }
    unsafe extern "C" fn entry_at(_registry: *mut u8, index: u32, entry_out: *mut *mut u8) { unsafe { entry_out.write(ENTRIES[index as usize]) } }
    unsafe extern "C" fn handler_is_active(handler: *mut u8) -> u32 { unsafe { ACTIVE[handler as usize - 1] } }
    unsafe extern "C" fn handler_dispatch(handler: *mut u8, _event: u32, output: *mut u32) {
        unsafe { DISPATCH_ORDER[DISPATCH_LEN] = handler as usize as u32; DISPATCH_LEN += 1; output.write((handler as usize as u32).wrapping_mul(3)); }
    }
    unsafe extern "C" fn notify_collection_get() -> *mut u8 { core::ptr::addr_of_mut!(NOTIFY_COLLECTION).cast() }
    unsafe extern "C" fn notify_item_at(_collection: *mut u8, _index: u32) -> *mut u8 { unsafe { NOTIFY_LISTENER } }
    unsafe extern "C" fn unused_prepare(_listener: *mut u8) {}
    unsafe extern "C" fn notify_result(_listener: *mut u8, _event: u32, output: *mut u32) { unsafe { output.write(0x20) } }

    fn install(count: u32) {
        unsafe {
            REGISTRY = [0, count];
            DISPATCH_LEN = 0;
            REGISTERED_LISTENER_DISPATCH_OPS = RegisteredListenerDispatchOps { registry_get, entry_at, handler_is_active, handler_dispatch };
            REGISTERED_LISTENER_NOTIFY_OPS = RegisteredListenerNotifyOps { collection_get: notify_collection_get, item_at: notify_item_at, prepare: unused_prepare, notify: notify_result };
        }
    }

    #[test]
    fn empty_registry_returns_listener_notification_result() {
        let _guard = TEST_LOCK.lock();
        install(0);
        assert_eq!(unsafe { registered_listener_dispatch(core::ptr::null_mut(), 0x40, core::ptr::null_mut()) }, 0x20);
        assert_eq!(unsafe { DISPATCH_LEN }, 0);
    }

    #[test]
    fn dispatches_only_active_handlers_and_adds_last_output() {
        let Some(slab) = try_map_u32_slab(hints::REGISTERED_LISTENER_DISPATCH, 0x1000) else { return; };
        let _guard = TEST_LOCK.lock();
        unsafe {
            slab.write_bytes(0, 0x1000);
            ENTRIES = [slab, slab.add(0x100), slab.add(0x200)];
            for index in 0..3 {
                let entry = ENTRIES[index];
                entry.add(ENTRY_HANDLER_OFFSET).cast::<u32>().write((index + 1) as u32);
            }
            ACTIVE = [1, 0, 1];
        }
        install(3);
        assert_eq!(unsafe { registered_listener_dispatch(core::ptr::null_mut(), 0x44, core::ptr::null_mut()) }, 0x29);
        assert_eq!(unsafe { &DISPATCH_ORDER[..DISPATCH_LEN] }, &[1, 3]);
    }
}
