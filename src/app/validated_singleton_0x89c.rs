//! `validated_singleton_0x89c_get` — original: `FUN_0820a570` @
//! **0x0820a570** (**92 code bytes** plus pool words @ 0x0820a5cc and
//! 0x0820a5d0 = **100 bytes true extent**; **9 direct `bl` call sites, all
//! unconditional — 0 predicated forms and 0 plain `b`**), verified by decoding
//! every ARM B/BL word in `work/firmware/osos.dec`. The next separately linked
//! entry is the 4-byte veneer at 0x0820a5d4.
//!
//! The validated 0x89c-byte singleton: load the cache at 0x089cb1dc; on NULL,
//! allocate 0x89c bytes through `operator_new`, construct through the local
//! veneer `FUN_0820a610`, and cache its return. A non-NULL constructed object
//! must pass `FUN_0820a4c0`; on failure the routine reloads the cache, passes
//! the destructor's return from `FUN_0820a61c` to `operator_delete`, clears the
//! cache, and returns NULL. A NULL allocation still reaches the construction
//! veneer; a NULL constructor result skips validation and retries on the next
//! call. The 0x083e9314 literal which the construction veneer supplies in r1
//! does not establish a recovered object identity, so this symbol records only
//! the verified singleton shape and allocation size.
//!
//! Deliberate deviation: host tests use a crate-local cache and recording
//! operations for the three unported lifecycle bodies. Target builds use the
//! original cache word and call the fixed retailOS addresses directly. The
//! allocator/deallocator are already ported and are called directly on every
//! build.

#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, addr_of_mut};

use crate::heap::veneers::{operator_delete, operator_new};

const RETAIL_CONSTRUCT: usize = 0x0820_a610;
const RETAIL_VALIDATE: usize = 0x0820_a4c0;
const RETAIL_DESTROY: usize = 0x0820_a61c;

/// Allocation size passed to `operator_new` by the original's pool word.
pub const VALIDATED_SINGLETON_0X89C_SIZE: usize = 0x89c;

/// The local construction veneer at 0x0820a610 supplies its fixed r1 literal.
pub type ValidatedSingletonConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;
/// `FUN_0820a4c0` accepts the constructed object and reports acceptance.
pub type ValidatedSingletonValidate = unsafe extern "C" fn(*mut u8) -> u32;
/// The destructor's return, rather than its input, feeds `operator_delete`.
pub type ValidatedSingletonDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Host lifecycle operations for the unported constructor, validator, and
/// destructor.
#[derive(Clone, Copy)]
pub struct ValidatedSingleton0x89cOps {
    pub construct: ValidatedSingletonConstruct,
    pub validate: ValidatedSingletonValidate,
    pub destroy: ValidatedSingletonDestroy,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct(object: *mut u8) -> *mut u8 {
    let function: ValidatedSingletonConstruct = core::mem::transmute(RETAIL_CONSTRUCT);
    function(object)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn validate(object: *mut u8) -> u32 {
    let function: ValidatedSingletonValidate = core::mem::transmute(RETAIL_VALIDATE);
    function(object)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy(object: *mut u8) -> *mut u8 {
    let function: ValidatedSingletonDestroy = core::mem::transmute(RETAIL_DESTROY);
    function(object)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_object: *mut u8) -> *mut u8 {
    panic!("install validated-singleton host operations before calling the getter")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_validate(_object: *mut u8) -> u32 {
    panic!("install validated-singleton host operations before calling the getter")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_object: *mut u8) -> *mut u8 {
    panic!("install validated-singleton host operations before calling the getter")
}

/// Host default before a test installs lifecycle equivalents.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VALIDATED_SINGLETON_0X89C_OPS: ValidatedSingleton0x89cOps =
    ValidatedSingleton0x89cOps {
        construct: missing_construct,
        validate: missing_validate,
        destroy: missing_destroy,
    };

/// Host-side lifecycle seam. Target builds call the three retailOS bodies.
#[cfg(not(target_os = "none"))]
pub static mut VALIDATED_SINGLETON_0X89C_OPS: ValidatedSingleton0x89cOps =
    DEFAULT_VALIDATED_SINGLETON_0X89C_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> ValidatedSingleton0x89cOps {
    core::ptr::read_volatile(addr_of!(VALIDATED_SINGLETON_0X89C_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct(object: *mut u8) -> *mut u8 {
    (host_ops().construct)(object)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn validate(object: *mut u8) -> u32 {
    (host_ops().validate)(object)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy(object: *mut u8) -> *mut u8 {
    (host_ops().destroy)(object)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_slot() -> *mut *mut u8 {
    0x089c_b1dc as *mut *mut u8
}

/// Host counterpart of the retail cache word at 0x089cb1dc.
#[cfg(not(target_os = "none"))]
pub static mut VALIDATED_SINGLETON_0X89C: *mut u8 = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_slot() -> *mut *mut u8 {
    addr_of_mut!(VALIDATED_SINGLETON_0X89C)
}

#[inline(always)]
unsafe fn validated_singleton_0x89c_with(
    allocate: unsafe extern "C" fn(usize) -> *mut u8,
    release: unsafe extern "C" fn(*mut u8),
) -> *mut u8 {
    let cache = cache_slot();
    if core::ptr::read_volatile(cache).is_null() {
        let object = construct(allocate(VALIDATED_SINGLETON_0X89C_SIZE));
        core::ptr::write_volatile(cache, object);
        if !object.is_null() && validate(object) == 0 {
            let cached = core::ptr::read_volatile(cache);
            if !cached.is_null() {
                release(destroy(cached));
            }
            core::ptr::write_volatile(cache, core::ptr::null_mut());
        }
    }
    core::ptr::read_volatile(cache)
}

/// Returns the singleton whose construction must pass its post-construction
/// validator before it remains cached.
///
/// # Safety
///
/// On target, this mutates the retail cache word at 0x089cb1dc and enters the
/// object's unported lifecycle routines. It has the original's no-lock,
/// no-reentrancy protection.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn validated_singleton_0x89c_get() -> *mut u8 {
    validated_singleton_0x89c_with(operator_new, operator_delete)
}

#[cfg(test)]
mod tests {
extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_RESULT: *mut u8 = core::ptr::null_mut();
    static mut DESTROY_RESULT: *mut u8 = core::ptr::null_mut();
    static mut VALIDATE_RESULT: u32 = 0;
    static mut EVENTS: [u8; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;
    static mut ALLOC_SIZE: usize = 0;
    static mut RELEASED: *mut u8 = core::ptr::null_mut();

    fn event(kind: u8) {
        unsafe {
            EVENTS[EVENT_COUNT] = kind;
            EVENT_COUNT += 1;
        }
    }

    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        ALLOC_SIZE = size;
        event(1);
        ALLOC_RESULT
    }

    unsafe extern "C" fn release(object: *mut u8) {
        RELEASED = object;
        event(4);
    }

    unsafe extern "C" fn construct(object: *mut u8) -> *mut u8 {
        assert_eq!(object, ALLOC_RESULT);
        event(2);
        CONSTRUCT_RESULT
    }

    unsafe extern "C" fn validate(object: *mut u8) -> u32 {
        assert_eq!(object, CONSTRUCT_RESULT);
        event(3);
        VALIDATE_RESULT
    }

    unsafe extern "C" fn destroy(object: *mut u8) -> *mut u8 {
        assert_eq!(object, CONSTRUCT_RESULT);
        event(5);
        DESTROY_RESULT
    }

    struct Reset {
        old_ops: ValidatedSingleton0x89cOps,
        old_cache: *mut u8,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(addr_of_mut!(VALIDATED_SINGLETON_0X89C_OPS), self.old_ops);
                core::ptr::write_volatile(addr_of_mut!(VALIDATED_SINGLETON_0X89C), self.old_cache);
            }
        }
    }

    unsafe fn install() -> Reset {
        let old_ops = core::ptr::read_volatile(addr_of!(VALIDATED_SINGLETON_0X89C_OPS));
        let old_cache = core::ptr::read_volatile(addr_of!(VALIDATED_SINGLETON_0X89C));
        core::ptr::write_volatile(
            addr_of_mut!(VALIDATED_SINGLETON_0X89C_OPS),
            ValidatedSingleton0x89cOps { construct, validate, destroy },
        );
        core::ptr::write_volatile(addr_of_mut!(VALIDATED_SINGLETON_0X89C), core::ptr::null_mut());
        ALLOC_RESULT = core::ptr::null_mut();
        CONSTRUCT_RESULT = core::ptr::null_mut();
        DESTROY_RESULT = core::ptr::null_mut();
        VALIDATE_RESULT = 0;
        EVENTS = [0; 8];
        EVENT_COUNT = 0;
        ALLOC_SIZE = 0;
        RELEASED = core::ptr::null_mut();
        Reset { old_ops, old_cache }
    }

    #[test]
    fn returns_cached_object_without_lifecycle_calls() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _reset = install();
            let cached = 0x1010usize as *mut u8;
            core::ptr::write_volatile(addr_of_mut!(VALIDATED_SINGLETON_0X89C), cached);
            assert_eq!(validated_singleton_0x89c_get(), cached);
            assert_eq!(EVENT_COUNT, 0);
        }
    }

    #[test]
    fn keeps_a_constructed_object_only_after_validation() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _reset = install();
            ALLOC_RESULT = 0x1110usize as *mut u8;
            CONSTRUCT_RESULT = 0x2220usize as *mut u8;
            VALIDATE_RESULT = 1;
            assert_eq!(validated_singleton_0x89c_with(allocate, release), CONSTRUCT_RESULT);
            assert_eq!(ALLOC_SIZE, VALIDATED_SINGLETON_0X89C_SIZE);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 3]);
            assert!(RELEASED.is_null());
        }
    }

    #[test]
    fn destroys_and_deletes_the_destructor_result_on_validation_failure() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _reset = install();
            ALLOC_RESULT = 0x1110usize as *mut u8;
            CONSTRUCT_RESULT = 0x2220usize as *mut u8;
            DESTROY_RESULT = 0x3330usize as *mut u8;
            assert!(validated_singleton_0x89c_with(allocate, release).is_null());
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 3, 5, 4]);
            assert_eq!(RELEASED, DESTROY_RESULT);
            assert!(VALIDATED_SINGLETON_0X89C.is_null());
        }
    }

    #[test]
    fn null_constructor_result_skips_validation_and_retries() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _reset = install();
            assert!(validated_singleton_0x89c_with(allocate, release).is_null());
            assert!(validated_singleton_0x89c_with(allocate, release).is_null());
            assert_eq!(ALLOC_SIZE, VALIDATED_SINGLETON_0X89C_SIZE);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 1, 2]);
            assert!(RELEASED.is_null());
        }
    }
}
