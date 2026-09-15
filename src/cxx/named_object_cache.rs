//! Lazily finding or constructing a named object in a container.
//!
//! `named_object_cache_ensure` — original: `FUN_0816c960` @ 0x0816c960
//! (104 bytes, `0x0816c960..0x0816c9c8`; six plain `bl` instructions to five
//! distinct callees, and no predicated `bl` instructions, verified from `osos.dec`).
//!
//! The cache owner keeps its container word at +0x70, cached object at +0x74,
//! and a `StringObject` key at +0x7c. A populated cache returns untouched.
//! Otherwise the retail body looks up the key, or allocates 0x90 bytes,
//! constructs the named object, registers it in the container, and caches it.
//! The lookup, construction, and registration targets remain unported and are
//! narrow firmware boundaries; host tests inject them. Rust cannot preserve
//! the retail tail-call layout through `operator_new` or the fixed-address
//! boundaries, but preserves their call order and unguarded pointer accesses.

#[cfg(target_os = "none")]
use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::heap::veneers::operator_new;

/// Reads the target-width `StringObject` payload at +4, matching
/// `string_object_c_str` @ 0x082a50b0 without applying the host's 8-byte
/// pointer layout to the owner's ARM-layout field at +0x7c.
#[inline(always)]
unsafe fn object_key_c_str(key: *const u8) -> *const u8 {
    #[cfg(target_os = "none")]
    {
        string_object_c_str(key.cast::<StringObject>())
    }
    #[cfg(not(target_os = "none"))]
    {
        key.add(4).cast::<u32>().read() as usize as *const u8
    }
}


const CONTAINER_OFFSET: usize = 0x70;
const CACHED_OBJECT_OFFSET: usize = 0x74;
const KEY_OFFSET: usize = 0x7c;
const NAMED_OBJECT_SIZE: usize = 0x90;

type NamedObjectLookup = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;
type NamedObjectConstruct = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;
type NamedObjectRegister = unsafe extern "C" fn(*mut u8, *mut u8);

unsafe extern "C" fn firmware_named_object_lookup(container: *mut u8, key: *const u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let lookup: NamedObjectLookup = core::mem::transmute(0x0829_9d20usize);
        lookup(container, key)
    }
    #[cfg(not(target_os = "none"))]
    {


        let _ = (container, key);
        core::ptr::null_mut()
    }
}
#[inline(always)]
unsafe fn read_target_ptr(field: *const u8) -> *mut u8 {
    field.cast::<u32>().read() as usize as *mut u8
}

#[inline(always)]
unsafe fn write_target_ptr(field: *mut u8, value: *mut u8) {
    field.cast::<u32>().write(value as usize as u32);
}

unsafe extern "C" fn firmware_named_object_construct(storage: *mut u8, key: *const u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let construct: NamedObjectConstruct = core::mem::transmute(0x0828_494cusize);
        construct(storage, key)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (storage, key);
        core::ptr::null_mut()
    }
}

unsafe extern "C" fn firmware_named_object_register(container: *mut u8, object: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let register: NamedObjectRegister = core::mem::transmute(0x0812_8468usize);
        register(container, object)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (container, object);
    }
}

static mut NAMED_OBJECT_LOOKUP: NamedObjectLookup = firmware_named_object_lookup;
static mut NAMED_OBJECT_CONSTRUCT: NamedObjectConstruct = firmware_named_object_construct;
static mut NAMED_OBJECT_REGISTER: NamedObjectRegister = firmware_named_object_register;

#[inline(always)]
unsafe fn named_object_lookup() -> NamedObjectLookup {
    core::ptr::read_volatile(core::ptr::addr_of!(NAMED_OBJECT_LOOKUP))
}
#[inline(always)]
unsafe fn named_object_construct() -> NamedObjectConstruct {
    core::ptr::read_volatile(core::ptr::addr_of!(NAMED_OBJECT_CONSTRUCT))
}
#[inline(always)]
unsafe fn named_object_register() -> NamedObjectRegister {
    core::ptr::read_volatile(core::ptr::addr_of!(NAMED_OBJECT_REGISTER))
}

/// Ensures that `owner` has its named object cached at +0x74.
///
/// # Safety
/// `owner` must be readable and writable through +0x74, contain a valid
/// `StringObject` at +0x7c, and its +0x70 container must meet the unported
/// lookup/register boundary contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn named_object_cache_ensure(owner: *mut u8) {
    let cached = owner.add(CACHED_OBJECT_OFFSET);
    if !read_target_ptr(cached).is_null() {
        return;
    }

    let container = read_target_ptr(owner.add(CONTAINER_OFFSET));
    let key = object_key_c_str(owner.add(KEY_OFFSET));
    let mut object = named_object_lookup()(container, key);
    if object.is_null() {
        let key = object_key_c_str(owner.add(KEY_OFFSET));
        object = named_object_construct()(operator_new(NAMED_OBJECT_SIZE), key);
        named_object_register()(container, object);
    }
    write_target_ptr(cached, object);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::NAMED_OBJECT_CACHE, 0x1000).map(|pointer| pointer as usize)
    });
    static mut LOOKUP_RESULT: *mut u8 = ptr::null_mut();
    static mut LOOKUP_CALLS: u32 = 0;
    static mut CONSTRUCT_STORAGE: *mut u8 = ptr::null_mut();
    static mut CONSTRUCT_KEY: *const u8 = ptr::null();
    static mut REGISTER_OBJECT: *mut u8 = ptr::null_mut();
    static mut REGISTER_CALLS: u32 = 0;
    static mut ALLOCATION: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn lookup_stub(_container: *mut u8, _key: *const u8) -> *mut u8 {
        LOOKUP_CALLS += 1;
        LOOKUP_RESULT
    }
    unsafe extern "C" fn construct_stub(storage: *mut u8, key: *const u8) -> *mut u8 {
        CONSTRUCT_STORAGE = storage;
        CONSTRUCT_KEY = key;
        storage
    }
    unsafe extern "C" fn register_stub(_container: *mut u8, object: *mut u8) {
        REGISTER_CALLS += 1;
        REGISTER_OBJECT = object;
    }
    unsafe extern "C" fn alloc_stub(_heap: *mut crate::heap::types::HeapDescriptorDescriptor, size: usize, tag: usize) -> *mut u8 {
        assert_eq!((size, tag), (NAMED_OBJECT_SIZE, 2));
        ALLOCATION
    }

    unsafe fn owner() -> *mut u8 {
        SLAB.expect("fixture mapping was checked") as *mut u8
    }

    unsafe fn reset() {
        owner().write_bytes(0, 0x1000);
        LOOKUP_RESULT = ptr::null_mut();
        LOOKUP_CALLS = 0;
        CONSTRUCT_STORAGE = ptr::null_mut();
        CONSTRUCT_KEY = ptr::null();
        REGISTER_OBJECT = ptr::null_mut();
        REGISTER_CALLS = 0;
        ALLOCATION = owner().add(0x200);
    }

    #[test]
    fn keeps_a_populated_cache_without_resolving_the_key() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("cxx/named_object_cache")); return; }
        unsafe {
            reset();
            let present = owner().add(0x300);
            write_target_ptr(owner().add(CACHED_OBJECT_OFFSET), present);
            named_object_cache_ensure(owner());
            assert_eq!(read_target_ptr(owner().add(CACHED_OBJECT_OFFSET)), present);
            assert_eq!(LOOKUP_CALLS, 0);
        }
    }

    #[test]
    fn constructs_registers_and_caches_when_lookup_misses() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("cxx/named_object_cache")); return; }
        unsafe {
            let old_lookup = NAMED_OBJECT_LOOKUP;
            let old_construct = NAMED_OBJECT_CONSTRUCT;
            let old_register = NAMED_OBJECT_REGISTER;
            let old_heap_ops = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
            reset();
            NAMED_OBJECT_LOOKUP = lookup_stub;
            NAMED_OBJECT_CONSTRUCT = construct_stub;
            NAMED_OBJECT_REGISTER = register_stub;
            let mut heap_ops = old_heap_ops;
            heap_ops.alloc = alloc_stub;
            HEAP_OPS = heap_ops;
            named_object_cache_ensure(owner());
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(CONSTRUCT_STORAGE, ALLOCATION);
            assert_eq!(CONSTRUCT_KEY, object_key_c_str(owner().add(KEY_OFFSET)));
            assert_eq!(REGISTER_CALLS, 1);
            assert_eq!(REGISTER_OBJECT, ALLOCATION);
            assert_eq!(read_target_ptr(owner().add(CACHED_OBJECT_OFFSET)), ALLOCATION);
            NAMED_OBJECT_LOOKUP = old_lookup;
            NAMED_OBJECT_CONSTRUCT = old_construct;
            NAMED_OBJECT_REGISTER = old_register;
            HEAP_OPS = old_heap_ops;
        }
    }

    #[test]
    fn caches_a_lookup_hit_without_constructing_or_registering() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("cxx/named_object_cache")); return; }
        unsafe {
            let old_lookup = NAMED_OBJECT_LOOKUP;
            reset();
            LOOKUP_RESULT = owner().add(0x380);
            NAMED_OBJECT_LOOKUP = lookup_stub;
            named_object_cache_ensure(owner());
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(REGISTER_CALLS, 0);
            assert_eq!(read_target_ptr(owner().add(CACHED_OBJECT_OFFSET)), LOOKUP_RESULT);
            NAMED_OBJECT_LOOKUP = old_lookup;
        }
    }
}
