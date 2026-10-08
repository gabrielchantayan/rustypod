//! Construction of a prefixed, active registry with its own observer.

use core::ptr;
use crate::app::class_registry::{registry_container_construct_default, registry_observer_base_construct, RegistryObserver, RegistryObserverVtable};
use crate::app::registry::Registry;
use crate::heap::veneers::operator_new;

#[repr(C)]
pub struct OwnedRegistry {
    pub prefix: u32,
    pub base: Registry,
    pub active: u8,
    pub reserved: [u8; 3],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 4] = [0; core::mem::offset_of!(OwnedRegistry, base)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 44] = [0; core::mem::offset_of!(OwnedRegistry, active)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 48] = [0; core::mem::size_of::<OwnedRegistry>()];

unsafe fn finish_construct(
    base: *mut Registry, vtable: *const usize,
    observer_vtable: *const RegistryObserverVtable,
    allocate: unsafe extern "C" fn(usize) -> *mut u8,
) -> *mut OwnedRegistry {
    let owner = base.cast::<u8>().sub(core::mem::offset_of!(OwnedRegistry, base)).cast::<OwnedRegistry>();
    ptr::write_volatile(ptr::addr_of_mut!((*base).vtable), vtable.cast());
    ptr::write_volatile(ptr::addr_of_mut!((*owner).active), 1);
    let enable: unsafe extern "C" fn(*mut Registry, u32) =
        core::mem::transmute(ptr::read_volatile(vtable.add(0x5c / 4)));
    enable(base, 1);
    let allocation = allocate(8).cast::<RegistryObserver>();
    // The original clears both allocation words before the base constructor.
    ptr::write_volatile(ptr::addr_of_mut!((*allocation).vtable), ptr::null());
    ptr::write_volatile(ptr::addr_of_mut!((*allocation).state), 0);
    let observer = registry_observer_base_construct(allocation);
    ptr::write_volatile(ptr::addr_of_mut!((*observer).vtable), observer_vtable);
    let vtable = ptr::read_volatile(ptr::addr_of!((*base).vtable)).cast::<usize>();
    let install: unsafe extern "C" fn(*mut Registry, *mut RegistryObserver) =
        core::mem::transmute(ptr::read_volatile(vtable.add(0x54 / 4)));
    install(base, observer);
    owner
}

/// Original: `FUN_08128484` @ 0x08128484. True extent 128 bytes:
/// 120 code bytes plus literals at 0x081284fc/0x08128500, followed by
/// the next independent PUSH at 0x08128504. Raw ARM-word scan verifies
/// 2 incoming plain BLs and 0 predicated BLs; body: 3 plain BLs,
/// 0 predicated BLs, 2 register BLXs.
///
/// Constructs the capacity-four registry at storage+4, derives the owner
/// from the returned base, installs vtable 0x08982784, sets base+40 active
/// to one, and dispatches slot +0x5c with one. Allocates and clears an
/// eight-byte observer, constructs its base, installs vtable 0x08988d20,
/// reloads the registry vtable, and dispatches +0x54 with the observer in
/// r1 (omitted by Ghidra). Returns the owner, ignoring dispatch results.
///
/// Deliberate deviation: repr(C) fields and word-indexed virtual slots
/// preserve ARM offsets while accommodating host pointers. The cold-image
/// vtable data cannot establish virtual target identities; runtime dispatch
/// is retained. All three known direct callees use their existing ports.
/// No allocation failure or NULL guards are introduced.
///
/// # Safety
/// Storage must hold an OwnedRegistry; firmware allocator and runtime
/// vtables must be initialized and satisfy their original method ABIs.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_registry_construct(storage: *mut OwnedRegistry) -> *mut OwnedRegistry {
    let base = registry_container_construct_default(ptr::addr_of_mut!((*storage).base));
    finish_construct(base, 0x0898_2784usize as *const _,
        0x0898_8d20usize as *const _, operator_new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVER: RegistryObserver = RegistryObserver { vtable: ptr::null(), state: 99 };
    static mut SECOND: [usize; 24] = [0; 24];
    static mut PHASE: u32 = 0;
    unsafe extern "C" fn enable(base: *mut Registry, enabled: u32) {
        assert_eq!(enabled, 1);
        let owner = base.cast::<u8>().sub(core::mem::offset_of!(OwnedRegistry, base)).cast::<OwnedRegistry>();
        assert_eq!((*owner).active, 1);
        assert_eq!(PHASE, 0);
        PHASE = 1;
        (*base).notify_enabled = 1;
        (*base).vtable = ptr::addr_of!(SECOND).cast();
    }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        assert_eq!(size, 8);
        assert_eq!(PHASE, 1);
        PHASE = 2;
        ptr::addr_of_mut!(OBSERVER).cast()
    }
    unsafe extern "C" fn install(base: *mut Registry, observer: *mut RegistryObserver) {
        assert_eq!(PHASE, 2);
        assert_eq!((*observer).state, 0);
        assert_eq!((*observer).vtable as usize, 0x0898_8d20);
        (*base).observer = observer.cast();
        PHASE = 3;
    }
    #[test]
    fn enabled_before_allocation_and_reloaded_vtable_installs_fresh_observer() {
        let _guard = LOCK.lock();
        unsafe {
            let mut first = [0usize; 24];
            first[23] = enable as usize;
            ptr::addr_of_mut!(SECOND).cast::<usize>().add(21).write(install as usize);
            let mut owner = OwnedRegistry {
                prefix: 0xfeed_beef,
                base: Registry { vtable: ptr::null(), container: [0x1234; 7], changed: 7,
                    notify_enabled: 0, reserved: [0xa5; 2], observer: ptr::null_mut() },
                active: 0, reserved: [0x5a; 3],
            };
            for initial in [0, 255] {
                owner.active = initial;
                OBSERVER.state = u32::MAX;
                PHASE = 0;
                let result = finish_construct(&mut owner.base, first.as_ptr(),
                    0x0898_8d20usize as *const _, allocate);
                assert_eq!(result, ptr::addr_of_mut!(owner));
                assert_eq!(PHASE, 3);
                assert_eq!(owner.prefix, 0xfeed_beef);
                assert_eq!(owner.base.container, [0x1234; 7]);
                assert_eq!(owner.base.changed, 7);
                assert_eq!(owner.base.reserved, [0xa5; 2]);
                assert_eq!(owner.reserved, [0x5a; 3]);
                assert_eq!(owner.base.observer, ptr::addr_of_mut!(OBSERVER).cast());
                assert_eq!((owner.active, owner.base.notify_enabled), (1, 1));
            }
        }
    }
}
