//! `registered_listener_notify` — original: `FUN_082753bc` @ `0x082753bc`.
//!
//! **120 bytes** (`0x082753bc..0x08275430`); `0x08275434` begins the next
//! independently linked function. Raw `osos.dec` contains five inbound direct
//! `bl` sites: `0x0812d6a8`, `0x0816c418`, `0x081a2114`, `0x081b985c`, and
//! `0x081f9a0c`; all are unconditional. The body has one plain direct `bl`
//! (to the unported collection getter at `0x08275434`), no predicated direct
//! `bl`, and three unconditional indirect `blx` calls through vtable slots.
//!
//! Algorithm: obtain the process-wide listener collection, walk its initial
//! `count` entries in ascending order, invoke each listener's slot `+0x2c`,
//! then invoke slot `+0x1c` with the event word and one stack-local output
//! word initialized to zero. The final output word is returned. There are no
//! NULL, count, or vtable guards.
//!
//! Deliberate deviation: the collection getter and all three virtual methods
//! are unported. Target builds call their verified raw addresses/slots;
//! host builds use a typed seam without assigning an unverified identity to
//! the collection getter.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_COLLECTION_GET: usize = 0x0827_5434;

/// Host model for the unported collection getter and virtual dispatches.
#[derive(Clone, Copy)]
pub struct RegisteredListenerNotifyOps {
    pub collection_get: unsafe extern "C" fn() -> *mut u8,
    pub item_at: unsafe extern "C" fn(*mut u8, u32) -> *mut u8,
    pub prepare: unsafe extern "C" fn(*mut u8),
    pub notify: unsafe extern "C" fn(*mut u8, u32, *mut u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collection_get() -> *mut u8 {
    panic!("install registered-listener notification host operations before calling")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_item_at(_collection: *mut u8, _index: u32) -> *mut u8 {
    panic!("install registered-listener notification host operations before calling")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_listener: *mut u8) {
    panic!("install registered-listener notification host operations before calling")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_notify(_listener: *mut u8, _event: u32, _output: *mut u32) {
    panic!("install registered-listener notification host operations before calling")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_REGISTERED_LISTENER_NOTIFY_OPS: RegisteredListenerNotifyOps = RegisteredListenerNotifyOps {
    collection_get: missing_collection_get,
    item_at: missing_item_at,
    prepare: missing_prepare,
    notify: missing_notify,
};

#[cfg(not(target_os = "none"))]
pub static mut REGISTERED_LISTENER_NOTIFY_OPS: RegisteredListenerNotifyOps =
    DEFAULT_REGISTERED_LISTENER_NOTIFY_OPS;

/// Notifies each listener registered in the process-wide collection.
///
/// # Safety
///
/// On target, the retail collection and every virtual table entry must be
/// valid. Host callers must install [`REGISTERED_LISTENER_NOTIFY_OPS`] and
/// supply a collection whose count word is at offset `+0x04`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_listener_notify(event: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        type CollectionGet = unsafe extern "C" fn() -> *mut u8;
        type ItemAt = unsafe extern "C" fn(*mut u8, u32) -> *mut *mut u8;
        type Prepare = unsafe extern "C" fn(*mut u8);
        type Notify = unsafe extern "C" fn(*mut u8, u32, *mut u32);

        let collection_get: CollectionGet = unsafe { core::mem::transmute(RETAIL_COLLECTION_GET) };
        let collection = unsafe { collection_get() };
        let count = unsafe { collection.add(4).cast::<u32>().read() };
        let mut output = 0;
        for index in 0..count {
            let collection_vtable = unsafe { collection.cast::<*const u8>().read_volatile() };
            let item_at: ItemAt = unsafe {
                (collection_vtable.add(0x40).cast::<ItemAt>()).read_volatile()
            };
            let listener = unsafe { item_at(collection, index).read() };
            let listener_vtable = unsafe { listener.cast::<*const u8>().read_volatile() };
            let prepare: Prepare = unsafe { (listener_vtable.add(0x2c).cast::<Prepare>()).read_volatile() };
            unsafe { prepare(listener) };
            let listener_vtable = unsafe { listener.cast::<*const u8>().read_volatile() };
            let notify: Notify = unsafe { (listener_vtable.add(0x1c).cast::<Notify>()).read_volatile() };
            unsafe { notify(listener, event, &mut output) };
        }
        output
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { core::ptr::read_volatile(addr_of!(REGISTERED_LISTENER_NOTIFY_OPS)) };
        let collection = unsafe { (ops.collection_get)() };
        let count = unsafe { collection.add(4).cast::<u32>().read() };
        let mut output = 0;
        for index in 0..count {
            let listener = unsafe { (ops.item_at)(collection, index) };
            unsafe { (ops.prepare)(listener) };
            unsafe { (ops.notify)(listener, event, &mut output) };
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut COLLECTION: [u32; 2] = [0; 2];
    static mut LISTENERS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut ORDER: [u32; 6] = [0; 6];
    static mut ORDER_LEN: usize = 0;

    unsafe extern "C" fn collection_get() -> *mut u8 { core::ptr::addr_of_mut!(COLLECTION).cast() }
    unsafe extern "C" fn item_at(_collection: *mut u8, index: u32) -> *mut u8 { unsafe { LISTENERS[index as usize] } }
    unsafe extern "C" fn prepare(listener: *mut u8) { unsafe { ORDER[ORDER_LEN] = listener as usize as u32; ORDER_LEN += 1; } }
    unsafe extern "C" fn notify(listener: *mut u8, event: u32, output: *mut u32) {
        unsafe { ORDER[ORDER_LEN] = event.wrapping_add(listener as usize as u32); ORDER_LEN += 1; output.write(event ^ listener as usize as u32); }
    }

    fn install(count: u32) {
        unsafe {
            COLLECTION = [0, count];
            ORDER_LEN = 0;
            REGISTERED_LISTENER_NOTIFY_OPS = RegisteredListenerNotifyOps { collection_get, item_at, prepare, notify };
        }
    }

    #[test]
    fn empty_collection_returns_initial_output_without_dispatch() {
        let _guard = TEST_LOCK.lock();
        install(0);
        assert_eq!(unsafe { registered_listener_notify(0x55) }, 0);
        assert_eq!(unsafe { ORDER_LEN }, 0);
    }

    #[test]
    fn every_listener_is_prepared_then_notified_in_index_order() {
        let _guard = TEST_LOCK.lock();
        unsafe { LISTENERS = [1usize as *mut u8, 2usize as *mut u8, 3usize as *mut u8]; }
        install(3);
        assert_eq!(unsafe { registered_listener_notify(0x40) }, 0x43);
        assert_eq!(unsafe { &ORDER[..ORDER_LEN] }, &[1, 0x41, 2, 0x42, 3, 0x43]);
    }
}
