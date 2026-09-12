//! `class6000_dirp_property_6066_or_default` — original: `FUN_08171ba0`
//! @ `0x08171ba0` (60 bytes: 52 instruction bytes plus literal-pool words at
//! `0x08171bd4` and `0x08171bd8`; the next function begins at `0x08171bdc`).
//! **8 `bl` call sites**, binary-scanned by decoding every ARM B/BL word in
//! `osos.dec`; all eight are unconditional `bl` instructions, with neither
//! predicated calls nor tail `b` references.
//!
//! Resolves the class-0x6000 singleton, then dispatches its vtable slot +0xe0
//! as `read_typed(store, 0x6066, 0x6000, "DirP")`. The returned object is
//! represented only by its first word: a non-NULL result yields that u32;
//! NULL yields the literal default 0x6067. The image does not establish what
//! the `"DirP"` resource kind or these 0x60xx values mean, so this port names
//! the verified key, kind, and fallback rather than inventing an identity.
//!
//! Deliberate deviation: the stock terminal virtual dispatch is expressed as
//! a Rust call, preserving its result; the dereference order and NULL fallback
//! are otherwise exact. As in stock, a missing class-0x6000 singleton faults
//! at its unguarded vtable load before a fallback can be returned.

use crate::app::class_8900::Class6000;
use crate::app::registry::instance_of_class_6000;
use crate::app::resource_chain::ResourceKind;

const CLASS_ID_6000: u32 = 0x6000;
const PROPERTY_KEY_6066: u32 = 0x6066;
const DEFAULT_PROPERTY_6067: u32 = 0x6067;
const RESOURCE_KIND_DIRP: ResourceKind = ResourceKind(0x4469_7250);

/// Returns the first word of class-0x6000's typed `"DirP"` property 0x6066,
/// or 0x6067 when its virtual lookup answers NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class6000_dirp_property_6066_or_default() -> u32 {
    let store = instance_of_class_6000() as *mut Class6000;
    let read_typed = (*(*store).vtable).read_typed;
    let value = read_typed(store, PROPERTY_KEY_6066, CLASS_ID_6000, RESOURCE_KIND_DIRP);
    if value.is_null() { DEFAULT_PROPERTY_6067 } else { *value }
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::class_8900::{Class6000ReadFn, Class6000ReadTypedFn, Class6000VTable};
    use crate::app::registry::{
        FrameworkObject, Registry, RegistryEntry, RegistryVtable, CLASS_REGISTRY,
    };
    use crate::testing::CLASS_REGISTRY_TEST_LOCK;
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TypedCall {
        store: *mut Class6000,
        key: u32,
        class_id: u32,
        kind: ResourceKind,
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CAST_CALLS: std::vec::Vec<u32> = std::vec::Vec::new();
    static mut TYPED_CALLS: std::vec::Vec<TypedCall> = std::vec::Vec::new();
    static mut TYPED_RESULT: *mut u32 = core::ptr::null_mut();
    static mut REGISTRY_ENTRY: RegistryEntry =
        RegistryEntry { class_id: 0, instance: core::ptr::null_mut() };

    /// The three decoded vtable views overlap: framework cast (+0x14),
    /// ordinary class-0x6000 read (+0xdc), and typed read (+0xe0).
    #[repr(C)]
    struct StoreVtable {
        slots_00: [Option<unsafe extern "C" fn()>; 5],
        cast_to_class: unsafe extern "C" fn(*mut FrameworkObject, u32) -> *mut u8,
        slots_18: [Option<unsafe extern "C" fn()>; 49],
        read: Class6000ReadFn,
        read_typed: Class6000ReadTypedFn,
    }

    #[repr(C)]
    struct Store {
        vtable: *const StoreVtable,
    }

    unsafe extern "C" fn recording_cast(
        this: *mut FrameworkObject,
        class_id: u32,
    ) -> *mut u8 {
        (*core::ptr::addr_of_mut!(CAST_CALLS)).push(class_id);
        if class_id == CLASS_ID_6000 { this.cast() } else { core::ptr::null_mut() }
    }

    unsafe extern "C" fn unreachable_read(
        _store: *mut Class6000,
        _key: u32,
        _class_id: u32,
    ) -> u32 {
        panic!("class6000_dirp_property_6066_or_default never dispatches slot +0xdc")
    }

    unsafe extern "C" fn recording_typed_read(
        store: *mut Class6000,
        key: u32,
        class_id: u32,
        kind: ResourceKind,
    ) -> *mut u32 {
        (*core::ptr::addr_of_mut!(TYPED_CALLS)).push(TypedCall { store, key, class_id, kind });
        core::ptr::read_volatile(core::ptr::addr_of!(TYPED_RESULT))
    }

    static STORE_VTABLE: StoreVtable = StoreVtable {
        slots_00: [None; 5],
        cast_to_class: recording_cast,
        slots_18: [None; 49],
        read: unreachable_read,
        read_typed: recording_typed_read,
    };

    unsafe extern "C" fn registry_index_of(_registry: *mut Registry, key: *const u32) -> i32 {
        let entry = core::ptr::read_volatile(core::ptr::addr_of!(REGISTRY_ENTRY));
        if entry.class_id == *key && !entry.instance.is_null() { 0 } else { -1 }
    }

    unsafe extern "C" fn registry_entry_at(
        _registry: *mut Registry,
        _index: i32,
        out: *mut RegistryEntry,
    ) -> *mut RegistryEntry {
        out.write(core::ptr::read_volatile(core::ptr::addr_of!(REGISTRY_ENTRY)));
        out
    }

    unsafe extern "C" fn unexpected_insert(_registry: *mut Registry, _entry: *const RegistryEntry) -> usize {
        panic!("lookup-only fixture must not insert")
    }

    unsafe extern "C" fn unexpected_assign(
        _registry: *mut Registry,
        _index: i32,
        _entry: *const RegistryEntry,
    ) -> usize {
        panic!("lookup-only fixture must not assign")
    }

    unsafe extern "C" fn unexpected_notify(_registry: *mut Registry) -> *mut u8 {
        panic!("lookup-only fixture must not notify")
    }

    static REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: unexpected_insert,
        unresolved_20: 0,
        assign_at: unexpected_assign,
        unresolved_28: [0; 5],
        entry_at: registry_entry_at,
        unresolved_40: [0; 3],
        index_of: registry_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: unexpected_notify,
        notify_deferred: unexpected_notify,
        notify_changed: unexpected_notify,
    };

    struct InstalledStore {
        _lock: std::sync::MutexGuard<'static, ()>,
        _registry_lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for InstalledStore {
        fn drop(&mut self) {
            unsafe {
                CLASS_REGISTRY.vtable = core::ptr::null();
                core::ptr::addr_of_mut!(REGISTRY_ENTRY).write(RegistryEntry {
                    class_id: 0,
                    instance: core::ptr::null_mut(),
                });
            }
        }
    }

    fn install(store: *mut Store, result: *mut u32) -> InstalledStore {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let registry_lock = CLASS_REGISTRY_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CAST_CALLS)).clear();
            (*core::ptr::addr_of_mut!(TYPED_CALLS)).clear();
            core::ptr::addr_of_mut!(TYPED_RESULT).write(result);
            core::ptr::addr_of_mut!(REGISTRY_ENTRY).write(RegistryEntry {
                class_id: CLASS_ID_6000,
                instance: store.cast(),
            });
            CLASS_REGISTRY.vtable = &REGISTRY_VTABLE;
        }
        InstalledStore { _lock: lock, _registry_lock: registry_lock }
    }

    #[test]
    fn returns_the_virtual_result_first_word_and_forwards_all_arguments() {
        let mut result = 0x6078;
        let mut store = Store { vtable: &STORE_VTABLE };
        let store_ptr = core::ptr::addr_of_mut!(store);
        let _installed = install(store_ptr, core::ptr::addr_of_mut!(result));

        let got = unsafe { class6000_dirp_property_6066_or_default() };

        assert_eq!(got, 0x6078);
        unsafe {
            assert_eq!(*core::ptr::addr_of!(CAST_CALLS), [CLASS_ID_6000]);
            assert_eq!(
                *core::ptr::addr_of!(TYPED_CALLS),
                [TypedCall {
                    store: store_ptr.cast(),
                    key: PROPERTY_KEY_6066,
                    class_id: CLASS_ID_6000,
                    kind: RESOURCE_KIND_DIRP,
                }],
            );
        }
    }

    #[test]
    fn null_virtual_result_uses_the_6067_fallback() {
        let mut store = Store { vtable: &STORE_VTABLE };
        let _installed = install(core::ptr::addr_of_mut!(store), core::ptr::null_mut());

        assert_eq!(unsafe { class6000_dirp_property_6066_or_default() }, DEFAULT_PROPERTY_6067);
        unsafe {
            assert_eq!((*core::ptr::addr_of!(TYPED_CALLS)).len(), 1);
        }
    }

    #[test]
    fn dirp_kind_literal_spells_dirp_big_endian() {
        assert_eq!(&RESOURCE_KIND_DIRP.0.to_be_bytes(), b"DirP");
    }
}
