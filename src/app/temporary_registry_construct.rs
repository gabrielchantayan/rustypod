//! Temporary registry used by the two note-processing paths.

use core::ptr;
use crate::app::class_registry::{registry_container_construct_default, registry_observer_base_construct, RegistryObserver, RegistryObserverVtable};
use crate::app::registry::Registry;
use crate::heap::veneers::operator_new;

#[repr(C)]
pub struct TemporaryRegistry {
    pub base: Registry,
    pub active: u8,
    pub reserved: [u8; 3],
    pub pending: u32,
    pub document: u32,
    pub client: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 56] = [0; core::mem::size_of::<TemporaryRegistry>()];

unsafe fn finish_construct(
    registry: *mut TemporaryRegistry, document: u32, client: u32,
    cache: *mut *mut RegistryObserver,
    vtable: *const usize, observer_vtable: *const RegistryObserverVtable,
    allocate: unsafe extern "C" fn(usize) -> *mut u8,
) -> *mut TemporaryRegistry {
    ptr::write_volatile(ptr::addr_of_mut!((*registry).base.vtable), vtable.cast());
    ptr::write_volatile(ptr::addr_of_mut!((*registry).active), 1);
    ptr::write_volatile(ptr::addr_of_mut!((*registry).pending), 0);
    ptr::write_volatile(ptr::addr_of_mut!((*registry).document), document);
    ptr::write_volatile(ptr::addr_of_mut!((*registry).client), client);
    if ptr::read_volatile(cache).is_null() {
        let observer = registry_observer_base_construct(allocate(8).cast());
        ptr::write_volatile(ptr::addr_of_mut!((*observer).vtable), observer_vtable);
        ptr::write_volatile(cache, observer);
        ((*observer_vtable).attach)(observer);
    }
    // Attach may replace the cache; each virtual call may replace the vtable.
    let observer = ptr::read_volatile(cache);
    let vtable = ptr::read_volatile(ptr::addr_of!((*registry).base.vtable)).cast::<usize>();
    let install: unsafe extern "C" fn(*mut TemporaryRegistry, *mut RegistryObserver) =
        core::mem::transmute(ptr::read_volatile(vtable.add(0x54 / 4)));
    install(registry, observer);
    let vtable = ptr::read_volatile(ptr::addr_of!((*registry).base.vtable)).cast::<usize>();
    let enable: unsafe extern "C" fn(*mut TemporaryRegistry, u32) =
        core::mem::transmute(ptr::read_volatile(vtable.add(0x5c / 4)));
    enable(registry, 1);
    registry
}

/// Original: `FUN_0812e1ec` @ 0x0812e1ec. True size 156 bytes:
/// 144 code bytes and 12 literal bytes; next function starts at 0x0812e288.
/// Raw-word scan verifies 2 incoming plain BLs, 0 predicated BLs; body has
/// 3 plain BLs, 0 predicated BLs, and 3 register BLX calls.
///
/// Constructs the capacity-four registry base, installs vtable 0x089825d4,
/// sets active=1 and pending=0, and records document/client. Lazily allocates
/// an eight-byte observer, constructs its base, installs vtable 0x08988cb8,
/// caches it at 0x089d0014 before attaching, reloads the cache, dispatches
/// registry slot +0x54 to install it, then reloads the vtable and dispatches
/// +0x5c with 1. Returns the base constructor's result, not a dispatch result.
/// Deliberate deviation: typed fields and word-indexed virtual slots keep
/// host pointers disjoint while retaining exact ARM layout. Virtual target
/// identities are unrecoverable from the stale cold-image vtable pages;
/// their original runtime pointers are retained, not replaced by guesses.
///
/// # Safety
/// Storage must hold a writable TemporaryRegistry. Retail runtime globals,
/// vtables and allocator must be initialized; no NULL guards are added.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn temporary_registry_construct(
    storage: *mut TemporaryRegistry, document: u32, client: u32,
) -> *mut TemporaryRegistry {
    let registry = registry_container_construct_default(storage.cast()).cast();
    finish_construct(registry, document, client, 0x089d_0014usize as *mut _,
        0x0898_25d4usize as *const _, 0x0898_8cb8usize as *const _, operator_new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CACHE: *mut RegistryObserver = ptr::null_mut();
    static mut ALLOCATIONS: u32 = 0;
    static mut OBSERVER: RegistryObserver = RegistryObserver { vtable: ptr::null(), state: 99 };
    static mut REPLACEMENT: RegistryObserver = RegistryObserver { vtable: ptr::null(), state: 7 };
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        assert_eq!(size, 8);
        ALLOCATIONS += 1;
        ptr::addr_of_mut!(OBSERVER).cast()
    }
    unsafe extern "C" fn attach(observer: *mut RegistryObserver) -> *mut u8 {
        assert_eq!(ptr::read_volatile(ptr::addr_of!(CACHE)), observer);
        assert_eq!((*observer).state, 0);
        CACHE = ptr::addr_of_mut!(REPLACEMENT);
        ptr::null_mut()
    }
    unsafe extern "C" fn install(registry: *mut TemporaryRegistry, observer: *mut RegistryObserver) {
        assert_eq!(observer, ptr::addr_of_mut!(REPLACEMENT));
        (*registry).base.observer = observer.cast();
        (*registry).base.vtable = ptr::addr_of!(SECOND).cast::<usize>().cast();
    }
    unsafe extern "C" fn enable(registry: *mut TemporaryRegistry, enabled: u32) {
        assert_eq!(enabled, 1);
        (*registry).base.notify_enabled = enabled as u8;
    }
    static OBSERVER_VTABLE: RegistryObserverVtable = RegistryObserverVtable {
        unresolved_00: [0; 6], attach, detach: attach,
    };
    // Function addresses cannot be cast to integers in const evaluation.
    static mut SECOND: [usize; 24] = [0; 24];
    #[test]
    fn cold_and_warm_cache_preserve_fields_and_honor_dispatch_mutations() {
        let _guard = LOCK.lock();
        unsafe {
            CACHE = ptr::null_mut();
            ALLOCATIONS = 0;
            ptr::addr_of_mut!(SECOND).cast::<usize>().add(23).write(enable as usize);
            let mut first = [0usize; 24];
            first[21] = install as usize;
            let mut object = TemporaryRegistry {
                base: Registry { vtable: ptr::null(), container: [0; 7], changed: 0,
                    notify_enabled: 0, reserved: [0; 2], observer: ptr::null_mut() },
                active: 99, reserved: [0xa5; 3], pending: 99, document: 0, client: 0,
            };
            for (document, client) in [(0, u32::MAX), (u32::MAX, 0)] {
                object.base.notify_enabled = 0;
                let result = finish_construct(&mut object, document, client,
                    ptr::addr_of_mut!(CACHE), first.as_ptr(), &OBSERVER_VTABLE, allocate);
                assert_eq!(result, ptr::addr_of_mut!(object));
                assert_eq!((object.active, object.pending, object.document, object.client),
                    (1, 0, document, client));
                assert_eq!(object.reserved, [0xa5; 3]);
                assert_eq!(object.base.observer, ptr::addr_of_mut!(REPLACEMENT).cast());
                assert_eq!(object.base.notify_enabled, 1);
                assert_eq!(ptr::read_volatile(ptr::addr_of!(ALLOCATIONS)), 1);
            }
            CACHE = ptr::null_mut();
        }
    }
}
