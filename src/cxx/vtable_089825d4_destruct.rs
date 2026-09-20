//! Destructor for the temporary registry constructed by `FUN_0812e1ec`.
//!
//! ## Ported function
//!
//! [`temporary_registry_destruct`] — original: `FUN_0839c6c4` @ 0x0839c6c4
//! (**36 bytes**: 32 bytes of code plus the vtable literal 0x089825d4 at
//! 0x0839c6e8; next function starts at 0x0839c6ec; **3 plain `bl` call
//! sites, 0 predicated `bl` call sites**, independently decoded from
//! `osos.dec`). It installs its derived vtable, calls the unported
//! `FUN_0839c610` validation teardown, then tail-branches to the ported
//! [`crate::app::class_registry::registry_container_destruct`]. The latter
//! returns `this`, preserving the target's return value.
//!
//! Deliberate deviation: host tests replace the unported validation call with
//! a seam to observe its order. Target builds call its verified stock address
//! directly, preserving the raw dependency without naming an unverified callee.

/// Vtable literal at 0x0839c6e8.
pub const TEMPORARY_REGISTRY_VTABLE: u32 = 0x0898_25d4;

/// The temporary registry's target-width object layout. `FUN_0812e1ec`
/// constructs 56 bytes and writes its two caller-context words at +0x30/+0x34.
#[repr(C)]
pub struct TemporaryRegistry {
    pub words: [u32; 14],
}

/// Host-test boundary for validation teardown at 0x0839c610.
#[cfg(not(target_os = "none"))]
pub static mut TEMPORARY_REGISTRY_VALIDATE: unsafe extern "C" fn(*mut TemporaryRegistry) =
    temporary_registry_validate_unported;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn temporary_registry_validate_unported(_registry: *mut TemporaryRegistry) {}

#[cfg(test)]
static mut TEMPORARY_REGISTRY_BASE_DESTRUCT: unsafe extern "C" fn(
    *mut TemporaryRegistry,
) -> *mut TemporaryRegistry = temporary_registry_base_destruct_host;

#[cfg(test)]
unsafe extern "C" fn temporary_registry_base_destruct_host(
    registry: *mut TemporaryRegistry,
) -> *mut TemporaryRegistry {
    registry
}

/// temporary_registry_destruct — original: `FUN_0839c6c4` @ 0x0839c6c4
/// (36 bytes: 32 bytes of instructions and the vtable literal at 0x0839c6e8;
/// 3 plain `bl` call sites, 0 predicated `bl` call sites).
///
/// Re-plants the temporary registry vtable, calls the stock validation
/// teardown at 0x0839c610, and destroys the registry-container base. Host
/// tests replace only that unported call to observe the raw instruction order.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn temporary_registry_destruct(
    registry: *mut TemporaryRegistry,
) -> *mut TemporaryRegistry {
    core::ptr::addr_of_mut!((*registry).words[0]).write_volatile(TEMPORARY_REGISTRY_VTABLE);
    #[cfg(target_os = "none")]
    let validate: unsafe extern "C" fn(*mut TemporaryRegistry) =
        core::mem::transmute(0x0839_c610usize);
    #[cfg(not(target_os = "none"))]
    let validate = core::ptr::read_volatile(core::ptr::addr_of!(TEMPORARY_REGISTRY_VALIDATE));
    validate(registry);

    #[cfg(test)]
    {
        let destruct = core::ptr::read_volatile(core::ptr::addr_of!(TEMPORARY_REGISTRY_BASE_DESTRUCT));
        return destruct(registry);
    }

    #[cfg(not(test))]
    crate::app::class_registry::registry_container_destruct(registry.cast()).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut VALIDATE_RECEIVER: *mut TemporaryRegistry = core::ptr::null_mut();
    static mut BASE_RECEIVER: *mut TemporaryRegistry = core::ptr::null_mut();
    static mut CALL_ORDER: u32 = 0;

    unsafe extern "C" fn validate(registry: *mut TemporaryRegistry) {
        assert_eq!(CALL_ORDER, 0);
        VALIDATE_RECEIVER = registry;
        CALL_ORDER = 1;
    }

    unsafe extern "C" fn destruct(registry: *mut TemporaryRegistry) -> *mut TemporaryRegistry {
        assert_eq!(CALL_ORDER, 1);
        BASE_RECEIVER = registry;
        CALL_ORDER = 2;
        registry
    }

    #[test]
    fn replants_vtable_then_validates_and_destroys_base() {
        let _guard = LOCK.lock();
        unsafe {
            let old_validate = TEMPORARY_REGISTRY_VALIDATE;
            let old_destruct = TEMPORARY_REGISTRY_BASE_DESTRUCT;
            TEMPORARY_REGISTRY_VALIDATE = validate;
            TEMPORARY_REGISTRY_BASE_DESTRUCT = destruct;
            VALIDATE_RECEIVER = core::ptr::null_mut();
            BASE_RECEIVER = core::ptr::null_mut();
            CALL_ORDER = 0;

            let mut registry = TemporaryRegistry { words: [0; 14] };
            registry.words[0] = 0xdead_beef;
            let result = temporary_registry_destruct(&mut registry);

            assert_eq!(result as usize, (&mut registry) as *mut TemporaryRegistry as usize);
            assert_eq!(registry.words[0], TEMPORARY_REGISTRY_VTABLE);
            assert_eq!(VALIDATE_RECEIVER as usize, (&mut registry) as *mut TemporaryRegistry as usize);
            assert_eq!(BASE_RECEIVER as usize, (&mut registry) as *mut TemporaryRegistry as usize);
            assert_eq!(CALL_ORDER, 2);
            TEMPORARY_REGISTRY_VALIDATE = old_validate;
            TEMPORARY_REGISTRY_BASE_DESTRUCT = old_destruct;
        }
    }
}
