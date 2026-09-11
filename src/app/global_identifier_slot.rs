//! `initialize_global_identifier_slot` — original: `FUN_081235dc` @
//! **0x081235dc** (32 bytes: eight ARM instructions from the `push` through
//! `pop`; the separately linked next function starts at 0x08123600). Ghidra's
//! 36-byte extent includes the next function's `push` word.
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds **10 direct
//! unconditional `bl` call sites** — 0x082b07a0, 0x082b07ac, 0x082b07b8,
//! 0x082b07c4, 0x082b07d0, 0x082b07dc, 0x082b07e8, 0x082b07f4, 0x082b0800,
//! and 0x082b080c — with no predicated form. One additional caller at
//! 0x082b081c is a direct tail `b`. Each direct caller supplies one of the
//! opaque low-valued identifiers 0x2406..0x27b6 and a distinct global word.
//!
//! Algorithm: obtain the shared opaque identifier-registry object through
//! `FUN_081f4e44`, initialize that object for the supplied identifier through
//! `FUN_081f4e9c`, store the identifier in `*slot`, and return `slot`. The
//! registry's concrete type and the two helpers' semantic identities are not
//! recovered, so this module names only their verified roles.
//!
//! Deliberate deviation: neither callee is ported. Target builds call their
//! fixed retailOS addresses through payload-safe indirect calls; host tests
//! use an injectable seam. This changes the direct `bl` instructions into
//! indirect `blx` calls, but preserves argument order, ordering, and result.

/// Fixed retailOS address of the opaque registry getter, `FUN_081f4e44`.
const RETAIL_IDENTIFIER_REGISTRY_GET: usize = 0x081f_4e44;

/// Fixed retailOS address of the opaque registry initializer, `FUN_081f4e9c`.
const RETAIL_IDENTIFIER_REGISTRY_INITIALIZE: usize = 0x081f_4e9c;

/// Host/target boundary for the two unported identifier-registry operations.
#[derive(Clone, Copy)]
pub struct IdentifierSlotInitializeOps {
    pub registry_get: unsafe extern "C" fn() -> *mut u8,
    pub registry_initialize: unsafe extern "C" fn(*mut u8, u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_registry_get() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_registry_initialize(_registry: *mut u8, _identifier: u32) {}

#[cfg(not(target_os = "none"))]
pub static mut IDENTIFIER_SLOT_INITIALIZE_OPS: IdentifierSlotInitializeOps =
    IdentifierSlotInitializeOps {
        registry_get: missing_registry_get,
        registry_initialize: missing_registry_initialize,
    };

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn identifier_registry_get() -> *mut u8 {
    let get: unsafe extern "C" fn() -> *mut u8 =
        core::mem::transmute(RETAIL_IDENTIFIER_REGISTRY_GET);
    get()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn identifier_registry_get() -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(IDENTIFIER_SLOT_INITIALIZE_OPS.registry_get))()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn identifier_registry_initialize(registry: *mut u8, identifier: u32) {
    let initialize: unsafe extern "C" fn(*mut u8, u32) =
        core::mem::transmute(RETAIL_IDENTIFIER_REGISTRY_INITIALIZE);
    initialize(registry, identifier)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn identifier_registry_initialize(registry: *mut u8, identifier: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(IDENTIFIER_SLOT_INITIALIZE_OPS.registry_initialize))(
        registry,
        identifier,
    )
}

/// `initialize_global_identifier_slot` — original: `FUN_081235dc` @
/// **0x081235dc** (32 bytes; 10 unconditional direct `bl` call sites plus one
/// direct tail `b`).
///
/// Calls the opaque shared identifier registry's getter and initializer in
/// that order, then stores `identifier` in `slot` and returns `slot`. Neither
/// pointer is NULL-guarded in retailOS: a NULL `slot` reaches the final store.
/// The registry getter's result also reaches its initializer unchanged.
///
/// # Safety
///
/// `slot` must be writable and four-byte aligned. The installed registry
/// operations must implement the retailOS contracts for their arguments.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn initialize_global_identifier_slot(
    slot: *mut u32,
    identifier: u32,
) -> *mut u32 {
    let registry = identifier_registry_get();
    identifier_registry_initialize(registry, identifier);
    slot.write(identifier);
    slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut REGISTRY: u8 = 0;
    static mut CALL_ORDER: [u8; 2] = [0; 2];
    static mut CALL_COUNT: usize = 0;
    static mut INITIALIZE_REGISTRY: *mut u8 = core::ptr::null_mut();
    static mut INITIALIZE_IDENTIFIER: u32 = 0;

    unsafe extern "C" fn recording_registry_get() -> *mut u8 {
        CALL_ORDER[CALL_COUNT] = 1;
        CALL_COUNT += 1;
        core::ptr::addr_of_mut!(REGISTRY)
    }

    unsafe extern "C" fn recording_registry_initialize(registry: *mut u8, identifier: u32) {
        CALL_ORDER[CALL_COUNT] = 2;
        CALL_COUNT += 1;
        INITIALIZE_REGISTRY = registry;
        INITIALIZE_IDENTIFIER = identifier;
    }

    unsafe fn reset_seam() {
        IDENTIFIER_SLOT_INITIALIZE_OPS = IdentifierSlotInitializeOps {
            registry_get: recording_registry_get,
            registry_initialize: recording_registry_initialize,
        };
        CALL_ORDER = [0; 2];
        CALL_COUNT = 0;
        INITIALIZE_REGISTRY = core::ptr::null_mut();
        INITIALIZE_IDENTIFIER = 0;
    }

    #[test]
    fn initializes_registry_before_storing_identifier_edges() {
        let _guard = TEST_LOCK.lock();
        for identifier in [0, u32::MAX] {
            let mut slot = !identifier;
            unsafe {
                reset_seam();
                let returned = initialize_global_identifier_slot(&mut slot, identifier);
                assert_eq!(returned, core::ptr::addr_of_mut!(slot));
                assert_eq!(CALL_COUNT, 2);
                assert_eq!(CALL_ORDER, [1, 2]);
                assert_eq!(INITIALIZE_REGISTRY, core::ptr::addr_of_mut!(REGISTRY));
                assert_eq!(INITIALIZE_IDENTIFIER, identifier);
            }
            assert_eq!(slot, identifier);
        }
    }
}
