//! Global readiness gate.
//!
//! `global_readiness_gate_is_ready` — original: `FUN_08087944` at
//! **0x08087944**. Raw `osos.dec` words establish the 48-byte extent
//! 0x08087944..0x08087973: `popne {r4,pc}` ends the executable body at
//! 0x0808796f, its literal-pool word is at 0x08087970, and the next function
//! begins at 0x08087974. The body has one plain direct outbound `bl`
//! (0x08149078) and no predicated direct `bl` instructions. Full-image call
//! site decoding finds three inbound plain `bl` calls and no predicated forms.
//!
//! Algorithm: read the runtime gate word at 0x089caed0; return zero when it is
//! zero, otherwise invoke the stock readiness predicate at 0x08149078 and
//! normalize its nonzero result to one. The global and predicate have no
//! established subsystem identity, so their names deliberately describe only
//! the verified gate behavior. Host builds replace both firmware boundaries
//! with test seams; target builds call the stock predicate through its fixed
//! address.
use core::ptr;

const GLOBAL_READINESS_GATE_ADDRESS: *const u32 = 0x089c_aed0usize as *const u32;
const RETAIL_READINESS_PREDICATE_ADDRESS: usize = 0x0814_9078;

type ReadinessPredicate = unsafe extern "C" fn() -> u32;

#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_READINESS_GATE: u32 = 0;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_readiness_predicate() -> u32 {
    panic!("global_readiness_gate_is_ready requires predicate 0x08149078")
}

#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_READINESS_PREDICATE: ReadinessPredicate = missing_readiness_predicate;

#[inline(always)]
unsafe fn global_readiness_gate_word() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { ptr::read_volatile(GLOBAL_READINESS_GATE_ADDRESS) }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(HOST_GLOBAL_READINESS_GATE)) }
    }
}

#[inline(always)]
unsafe fn readiness_predicate() -> u32 {
    #[cfg(target_os = "none")]
    {
        let predicate: ReadinessPredicate = unsafe { core::mem::transmute(RETAIL_READINESS_PREDICATE_ADDRESS) };
        unsafe { predicate() }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(GLOBAL_READINESS_PREDICATE))() }
    }
}

/// `global_readiness_gate_is_ready` — original: `FUN_08087944` at 0x08087944.
///
/// # Safety
///
/// Firmware execution requires 0x089caed0 to be readable and, when nonzero,
/// requires the retail predicate at 0x08149078 to be callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_readiness_gate_is_ready() -> u32 {
    if unsafe { global_readiness_gate_word() } == 0 {
        return 0;
    }

    (unsafe { readiness_predicate() } != 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PREDICATE_RESULT: u32 = 0;
    static mut PREDICATE_CALLS: u32 = 0;

    unsafe extern "C" fn predicate() -> u32 {
        unsafe {
            PREDICATE_CALLS += 1;
            PREDICATE_RESULT
        }
    }

    #[test]
    fn zero_gate_short_circuits_without_calling_the_predicate() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            HOST_GLOBAL_READINESS_GATE = 0;
            GLOBAL_READINESS_PREDICATE = predicate;
            PREDICATE_CALLS = 0;
        }

        assert_eq!(unsafe { global_readiness_gate_is_ready() }, 0);
        assert_eq!(unsafe { PREDICATE_CALLS }, 0);
    }

    #[test]
    fn nonzero_gate_normalizes_predicate_results() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            HOST_GLOBAL_READINESS_GATE = 0x1234_5678;
            GLOBAL_READINESS_PREDICATE = predicate;
            PREDICATE_CALLS = 0;
            PREDICATE_RESULT = 0;
        }
        assert_eq!(unsafe { global_readiness_gate_is_ready() }, 0);

        unsafe { PREDICATE_RESULT = u32::MAX; }
        assert_eq!(unsafe { global_readiness_gate_is_ready() }, 1);
        assert_eq!(unsafe { PREDICATE_CALLS }, 2);

        unsafe {
            HOST_GLOBAL_READINESS_GATE = 0;
            GLOBAL_READINESS_PREDICATE = missing_readiness_predicate;
        }
    }
}
