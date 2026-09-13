//! `type_handler_lookup` — original: `FUN_083eab08` @ **0x083eab08**
//! (32 bytes of code plus literal-pool words at `0x083eab28` and
//! `0x083eab2c`: 40 bytes of true extent, `0x083eab08..0x083eab30`).
//!
//! The wrapper asks the unported typed-handler registry at `0x082a7280` for
//! the handler selected by the four-word type identifier at `0x08a0fbe0`.
//! It fixes the registry arguments to `1` and `0x20`, and supplies the raw
//! fallback entry `0x083ab410`; that entry's identity is not established.
//! The helper result returns unchanged.
//!
//! **Six direct `bl` call sites, all unconditional and no predicated forms**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`:
//! `0x083d8dd8`, `0x083d8e08`, `0x083d8f1c`, `0x083d923c`, `0x083d9408`,
//! and `0x083d9610`.
//!
//! Deliberate deviation: the typed-handler registry remains unported. Target
//! builds call its fixed retailOS address; host tests install a volatile seam.

#[cfg(not(target_os = "none"))]
use core::ptr;

/// Firmware load address of the unported typed-handler registry.
pub const TYPED_HANDLER_LOOKUP_ADDRESS: usize = 0x082a_7280;
const HANDLER_TYPE_ID_ADDRESS: usize = 0x08a0_fbe0;
const DEFAULT_HANDLER_ENTRY_ADDRESS: usize = 0x083a_b410;
const HANDLER_LOOKUP_DIRECTION: u32 = 1;
const HANDLER_LOOKUP_FLAGS: u32 = 0x20;

/// ABI of `FUN_082a7280`, including the default entry passed in the fifth
/// argument slot by this wrapper.
pub type TypedHandlerLookup = unsafe extern "C" fn(
    registry: *mut *mut u8,
    type_id: *const u32,
    direction: u32,
    flags: u32,
    default_entry: usize,
) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn typed_handler_registry_lookup(
    registry: *mut *mut u8,
    type_id: *const u32,
    direction: u32,
    flags: u32,
    default_entry: usize,
) -> *mut u8 {
    let lookup: TypedHandlerLookup = core::mem::transmute(TYPED_HANDLER_LOOKUP_ADDRESS);
    lookup(registry, type_id, direction, flags, default_entry)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_typed_handler_registry_lookup(
    _registry: *mut *mut u8,
    _type_id: *const u32,
    _direction: u32,
    _flags: u32,
    _default_entry: usize,
) -> *mut u8 {
    panic!("install typed-handler lookup host seam before calling this wrapper")
}

/// Active host boundary for the unported typed-handler registry.
#[cfg(not(target_os = "none"))]
pub static mut TYPED_HANDLER_LOOKUP: TypedHandlerLookup = missing_typed_handler_registry_lookup;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn typed_handler_registry_lookup(
    registry: *mut *mut u8,
    type_id: *const u32,
    direction: u32,
    flags: u32,
    default_entry: usize,
) -> *mut u8 {
    let lookup = ptr::read_volatile(ptr::addr_of!(TYPED_HANDLER_LOOKUP));
    lookup(registry, type_id, direction, flags, default_entry)
}

#[inline(always)]
fn handler_type_id() -> *const u32 {
    #[cfg(target_os = "none")]
    {
        HANDLER_TYPE_ID_ADDRESS as *const u32
    }

    #[cfg(not(target_os = "none"))]
    {
        static TYPE_ID: [u32; 4] = [0x1ecc_4574, 0xc6ba_ba25, 0x334f_e7ef, 0x6685_372e];
        TYPE_ID.as_ptr()
    }
}

/// Looks up the handler for this wrapper's fixed, four-word type identifier.
///
/// # Safety
///
/// `registry` must satisfy the unported registry helper's contract. The
/// returned opaque handler pointer is owned and interpreted by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn type_handler_lookup(registry: *mut *mut u8) -> *mut u8 {
    typed_handler_registry_lookup(
        registry,
        handler_type_id(),
        HANDLER_LOOKUP_DIRECTION,
        HANDLER_LOOKUP_FLAGS,
        DEFAULT_HANDLER_ENTRY_ADDRESS,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static LOOKUP_LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP_CALL: Option<(*mut *mut u8, [u32; 4], u32, u32, usize)> = None;
    static mut LOOKUP_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_lookup(
        registry: *mut *mut u8,
        type_id: *const u32,
        direction: u32,
        flags: u32,
        default_entry: usize,
    ) -> *mut u8 {
        LOOKUP_CALL = Some((registry, [type_id.read(), type_id.add(1).read(), type_id.add(2).read(), type_id.add(3).read()], direction, flags, default_entry));
        LOOKUP_RESULT
    }

    fn install_recorder(result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = LOOKUP_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(LOOKUP_CALL).write(None);
            addr_of_mut!(LOOKUP_RESULT).write(result);
            addr_of_mut!(TYPED_HANDLER_LOOKUP).write(recording_lookup);
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(TYPED_HANDLER_LOOKUP).write(missing_typed_handler_registry_lookup);
        }
        drop(guard);
    }

    #[test]
    fn forwards_fixed_identifier_and_registry_arguments() {
        let mut registry_value = 0x1234usize as *mut u8;
        let result = 0x4321usize as *mut u8;
        let guard = install_recorder(result);

        let returned = unsafe { type_handler_lookup(addr_of_mut!(registry_value)) };

        unsafe {
            assert_eq!(
                addr_of!(LOOKUP_CALL).read(),
                Some((
                    addr_of_mut!(registry_value),
                    [0x1ecc_4574, 0xc6ba_ba25, 0x334f_e7ef, 0x6685_372e],
                    1,
                    0x20,
                    0x083a_b410,
                ))
            );
        }
        assert_eq!(returned, result);
        restore_default(guard);
    }

    #[test]
    fn forwards_null_registry_without_a_wrapper_guard() {
        let result = 0x7654usize as *mut u8;
        let guard = install_recorder(result);

        let returned = unsafe { type_handler_lookup(core::ptr::null_mut()) };

        unsafe {
            assert_eq!(
                addr_of!(LOOKUP_CALL).read(),
                Some((
                    core::ptr::null_mut(),
                    [0x1ecc_4574, 0xc6ba_ba25, 0x334f_e7ef, 0x6685_372e],
                    1,
                    0x20,
                    0x083a_b410,
                ))
            );
        }
        assert_eq!(returned, result);
        restore_default(guard);
    }
}
