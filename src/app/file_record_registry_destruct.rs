//! File-record registry destructor.
//!
//! `file_record_registry_destruct` — original: `FUN_08123560` @
//! **0x08123560** (120 bytes exactly, `0x08123560..0x081235d8`; the next
//! real function begins at `0x081235d8`, despite Ghidra's 124-byte extent).
//! Decoding every ARM B/BL word in `osos.dec` finds four direct incoming
//! plain `bl` calls and no predicated direct `bl` calls. The body makes three
//! direct `bl` calls, plus two predicated indirect `blx` calls through vtable
//! slot `+0x04`.
//!
//! It releases the optional object at `this+0x2c`, walks the file-record
//! registry with the shared iterator, releases every yielded node through the
//! same vtable slot, drops the iterator state, then chains to
//! `registry_container_destruct`. The indirect targets remain unresolved
//! runtime data. Deliberate deviation: host dispatch uses widened native
//! pointers at the observed target offsets; ARM reads the original u32 words.

use crate::app::class_registry::registry_container_destruct;
use crate::app::registry::Registry;
use crate::app::vtable_set::{file_record_iterator_begin, file_record_iterator_next, iterator_state_cleanup};

const AUXILIARY_OBJECT_OFFSET: usize = 0x2c;
const RELEASE_VTABLE_INDEX: usize = 1;

type ReleaseMethod = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_object(object: *mut u8) {
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let method: ReleaseMethod = core::mem::transmute(vtable.add(RELEASE_VTABLE_INDEX).read_volatile() as usize);
    method(object);
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostReleaseVtable {
    pub unresolved_00: usize,
    pub release: ReleaseMethod,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostReleaseObject {
    pub vtable: *const HostReleaseVtable,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_object(object: *mut u8) {
    let object = &*object.cast::<HostReleaseObject>();
    ((*object.vtable).release)(object as *const HostReleaseObject as *mut u8);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn auxiliary_object(this: *mut u8) -> *mut u8 {
    this.add(AUXILIARY_OBJECT_OFFSET).cast::<u32>().read_volatile() as usize as *mut u8
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn auxiliary_object(this: *mut u8) -> *mut u8 {
    this.add(AUXILIARY_OBJECT_OFFSET).cast::<*mut u8>().read_unaligned()
}

/// Releases all objects owned by a file-record registry, then destructs its
/// registry-container base.
///
/// # Safety
///
/// `this` must be a writable file-record registry. Its word at `+0x2c` and
/// every non-NULL node produced by the iterator must be an object with a
/// callable vtable slot `+0x04`; no pointer is checked by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn file_record_registry_destruct(this: *mut u8) -> *mut u8 {
    let auxiliary = auxiliary_object(this);
    if !auxiliary.is_null() {
        release_object(auxiliary);
    }

    let mut iterator = [0u32; 6];
    let mut key = 0u32;
    let mut node = core::ptr::null_mut::<u8>();
    file_record_iterator_begin(iterator.as_mut_ptr(), this);
    while file_record_iterator_next(iterator.as_mut_ptr(), &mut key, (&mut node).cast()) != 0 {
        if !node.is_null() {
            release_object(node);
        }
        node = core::ptr::null_mut();
    }
    iterator_state_cleanup(iterator.as_mut_ptr().add(1));
    registry_container_destruct(this.cast::<Registry>()).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::class_registry::{RegistryObserver, RegistryObserverVtable};
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::{Mutex, MutexGuard};

    const SLAB_LEN: usize = 0x1000;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASED: usize = 0;
    static mut RELEASED_OBJECT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn release(object: *mut u8) {
        RELEASED += 1;
        RELEASED_OBJECT = object;
    }

    unsafe extern "C" fn detach(observer: *mut RegistryObserver) -> *mut u8 { observer.cast() }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = LOCK.lock();
        unsafe {
            RELEASED = 0;
            RELEASED_OBJECT = core::ptr::null_mut();
        }
        Bench { _lock: lock }
    }

    #[test]
    fn releases_nonnull_auxiliary_and_skips_null_nodes() {
        let _bench = bench();
        let Some(slab) = try_map_u32_slab(hints::FILE_RECORD_REGISTRY_DESTRUCT, SLAB_LEN) else {
            return;
        };
        unsafe {
            let release_vtable = HostReleaseVtable { unresolved_00: 0, release };
            let mut auxiliary = HostReleaseObject { vtable: &release_vtable };
            let observer_vtable = RegistryObserverVtable { unresolved_00: [0; 6], attach: detach, detach };
            let mut observer = RegistryObserver { vtable: &observer_vtable, state: 0 };
            let registry = slab.cast::<Registry>();
            registry.write(Registry {
                vtable: core::ptr::null(),
                container: [0; 7],
                changed: 0,
                notify_enabled: 0,
                reserved: [0; 2],
                observer: (&mut observer) as *mut RegistryObserver as *mut u8,
            });
            slab.add(AUXILIARY_OBJECT_OFFSET).cast::<*mut u8>()
                .write_unaligned((&mut auxiliary) as *mut HostReleaseObject as *mut u8);

            assert_eq!(file_record_registry_destruct(slab), slab);
            assert_eq!(RELEASED, 1);
            assert_eq!(RELEASED_OBJECT, (&mut auxiliary) as *mut HostReleaseObject as *mut u8);
        }
    }
}
