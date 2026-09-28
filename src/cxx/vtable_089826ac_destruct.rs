//! `vtable_089826ac_destruct` — retailOS `FUN_0839c7ac` @ `0x0839c7ac`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes eight ARM instruction words from `0x0839c7ac`
//! through the tail `b` at `0x0839c7cc`, followed by the vtable literal
//! `0x089826ac` at `0x0839c7d0`; `0x0839c7d4` begins the next real function.
//! The true size is **36 bytes**. The body has one plain direct `bl` to the
//! validation helper at `0x0839c6ec` and one tail `b` to
//! [`crate::app::class_registry::registry_container_destruct`] at
//! `0x08135380`. An independent raw-ARM decode finds two inbound plain `bl`
//! sites (`0x0811d9d0`, `0x08135a90`) and no predicated inbound `bl` sites.
//!
//! ## Algorithm
//!
//! Install this derived destruction vtable, validate that the registry has no
//! live entries, then tail-chain into the registry-container destructor. The
//! class identity is not established, so the name describes the verified
//! vtable destructor role. Deliberate deviation: host tests replace the
//! unported validation helper and final direct tail call; target builds call
//! their verified retailOS addresses.

/// Target-width layout required by the validation helper at `0x0839c6ec`.
/// Its byte flag is at +0x28, so the object occupies at least eleven words.
#[repr(C)]
pub struct ValidatedRegistry {
    pub words: [u32; 11],
}

const VTABLE_WORD: u32 = 0x0898_26ac;

/// Host-test boundary for the unported validation helper at `0x0839c6ec`.
#[cfg(not(target_os = "none"))]
pub static mut VALIDATED_REGISTRY_VALIDATE: unsafe extern "C" fn(*mut ValidatedRegistry) =
    validated_registry_validate_unported;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn validated_registry_validate_unported(_registry: *mut ValidatedRegistry) {}

#[cfg(test)]
unsafe extern "C" fn host_registry_container_destruct(
    registry: *mut ValidatedRegistry,
) -> *mut ValidatedRegistry {
    registry
}

/// Host-only substitute for the direct tail branch to registry destruction.
#[cfg(test)]
static mut REGISTRY_CONTAINER_DESTRUCT: unsafe extern "C" fn(
    *mut ValidatedRegistry,
) -> *mut ValidatedRegistry = host_registry_container_destruct;

/// Installs the destruction vtable, validates the registry, and tail-chains
/// into the registry-container destructor.
///
/// Original: `FUN_0839c7ac` @ `0x0839c7ac` (36 bytes; two plain inbound `bl`
/// sites, no predicated inbound `bl` sites).
///
/// # Safety
///
/// `registry` must point to a writable target-layout registry. No NULL guard
/// exists in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_089826ac_destruct(
    registry: *mut ValidatedRegistry,
) -> *mut ValidatedRegistry {
    core::ptr::addr_of_mut!((*registry).words[0]).write_volatile(VTABLE_WORD);
    #[cfg(target_os = "none")]
    let validate: unsafe extern "C" fn(*mut ValidatedRegistry) =
        core::mem::transmute(0x0839_c6ecusize);
    #[cfg(not(target_os = "none"))]
    let validate = core::ptr::read_volatile(core::ptr::addr_of!(VALIDATED_REGISTRY_VALIDATE));
    validate(registry);

    #[cfg(test)]
    {
        let destruct = core::ptr::read_volatile(core::ptr::addr_of!(REGISTRY_CONTAINER_DESTRUCT));
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
    static mut VALIDATE_RECEIVER: *mut ValidatedRegistry = core::ptr::null_mut();
    static mut DESTRUCT_RECEIVER: *mut ValidatedRegistry = core::ptr::null_mut();
    static mut CALL_ORDER: u32 = 0;

    unsafe extern "C" fn validate(registry: *mut ValidatedRegistry) {
        assert_eq!(CALL_ORDER, 0);
        assert_eq!((*registry).words[0], VTABLE_WORD);
        VALIDATE_RECEIVER = registry;
        CALL_ORDER = 1;
    }

    unsafe extern "C" fn destruct(registry: *mut ValidatedRegistry) -> *mut ValidatedRegistry {
        assert_eq!(CALL_ORDER, 1);
        DESTRUCT_RECEIVER = registry;
        CALL_ORDER = 2;
        registry
    }

    #[test]
    fn replants_vtable_then_validates_and_destroys_base() {
        let _guard = LOCK.lock();
        unsafe {
            let old_validate = VALIDATED_REGISTRY_VALIDATE;
            let old_destruct = REGISTRY_CONTAINER_DESTRUCT;
            VALIDATED_REGISTRY_VALIDATE = validate;
            REGISTRY_CONTAINER_DESTRUCT = destruct;
            VALIDATE_RECEIVER = core::ptr::null_mut();
            DESTRUCT_RECEIVER = core::ptr::null_mut();
            CALL_ORDER = 0;

            let mut registry = ValidatedRegistry { words: [0; 11] };
            registry.words[0] = 0xdead_beef;
            let result = vtable_089826ac_destruct(&mut registry);

            assert_eq!(result as usize, (&mut registry) as *mut ValidatedRegistry as usize);
            assert_eq!(registry.words[0], VTABLE_WORD);
            assert_eq!(VALIDATE_RECEIVER as usize, (&mut registry) as *mut ValidatedRegistry as usize);
            assert_eq!(DESTRUCT_RECEIVER as usize, (&mut registry) as *mut ValidatedRegistry as usize);
            assert_eq!(CALL_ORDER, 2);
            VALIDATED_REGISTRY_VALIDATE = old_validate;
            REGISTRY_CONTAINER_DESTRUCT = old_destruct;
        }
    }
}
