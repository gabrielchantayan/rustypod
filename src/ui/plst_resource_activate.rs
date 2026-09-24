//! 'plst' UI-element resource activation.
//!
//! - `plst_resource_activate` — original: `FUN_0806cf80` @ `0x0806cf80`
//!   (136 bytes including the mutex literal at `0x0806d004`; 132 code bytes;
//!   next function starts at `0x0806d008`). Verified call count: 3 inbound
//!   direct `bl` calls, all unconditional; the body has 5 unconditional `bl`
//!   instructions and no predicated `bl`.

use core::ptr;

#[cfg(target_os = "none")]
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock};
use crate::kernel::posix_mutex::PosixMutex;

use super::plst_class_check::ui_element_is_plst_class;

const RESOURCE_MUTEX_ADDRESS: usize = 0x08a7_74c0;
const RESOURCE_PENDING_OFFSET: usize = 0x0c;
const RESOURCE_STATE_OFFSET: usize = 0x1c;
const RESOURCE_FLAGS_OFFSET: usize = 0x1ac;
const RESOURCE_MODE_OFFSET: usize = 0x1ae;
const RESOURCE_ACTIVE_FLAG: u8 = 1;

pub type PlstResourceGate = unsafe extern "C" fn(*mut u8, u32) -> u32;
pub type PlstResourceActivate = unsafe extern "C" fn(*mut u8, u32) -> u32;
pub type PlstResourceMutexOp = unsafe extern "C" fn(*mut PosixMutex);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_plst_resource_gate(resource: *mut u8, mode: u32) -> u32 {
    let call: PlstResourceGate = core::mem::transmute(0x0806_c228usize);
    call(resource, mode)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_plst_resource_gate(_resource: *mut u8, _mode: u32) -> u32 {
    0
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_plst_resource_activate(resource: *mut u8, mode: u32) -> u32 {
    let call: PlstResourceActivate = core::mem::transmute(0x080d_3570usize);
    call(resource, mode)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_plst_resource_activate(_resource: *mut u8, _mode: u32) -> u32 {
    0
}

unsafe extern "C" fn retail_plst_resource_lock(_mutex: *mut PosixMutex) {
    #[cfg(target_os = "none")]
    posix_mutex_lock(_mutex);
}

unsafe extern "C" fn retail_plst_resource_unlock(_mutex: *mut PosixMutex) {
    #[cfg(target_os = "none")]
    posix_mutex_unlock(_mutex);
}

/// Calls outside this one-function port.
///
/// Target builds use the canonical mutex ports and the two verified but
/// unported call addresses. Host tests replace the boundary to observe order
/// and arguments without constructing the firmware's global mutex.
#[derive(Clone, Copy)]
pub struct PlstResourceActivateOps {
    pub lock: PlstResourceMutexOp,
    pub gate: PlstResourceGate,
    pub activate: PlstResourceActivate,
    pub unlock: PlstResourceMutexOp,
}

pub const DEFAULT_PLST_RESOURCE_ACTIVATE_OPS: PlstResourceActivateOps = PlstResourceActivateOps {
    lock: retail_plst_resource_lock,
    gate: retail_plst_resource_gate,
    activate: retail_plst_resource_activate,
    unlock: retail_plst_resource_unlock,
};

pub static mut PLST_RESOURCE_ACTIVATE_OPS: PlstResourceActivateOps =
    DEFAULT_PLST_RESOURCE_ACTIVATE_OPS;

#[inline(always)]
fn plst_resource_activate_ops() -> PlstResourceActivateOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(PLST_RESOURCE_ACTIVATE_OPS)) }
}

/// plst_resource_activate — original: `FUN_0806cf80` @ `0x0806cf80`
/// (136 bytes including its mutex literal; 132 instruction bytes).
///
/// Raw decoding of `osos.dec` establishes that code ends at `0x0806d004`; its
/// mutex literal occupies `0x0806d004`, and the next independent function
/// begins at `0x0806d008`. Decoding every ARM `B`/`BL` word finds three inbound
/// direct `bl` calls, all plain, plus five outgoing plain `bl` calls and no
/// predicated `bl` in this body.
///
/// Algorithm: under the resource mutex, require the 'plst' class, active flag
/// at `+0x1ac`, no state word at `+0x1c`, a zero result from `0x0806c228` when
/// passed `resource+0x0c` and mode zero, and byte `+0x1ae == 1`. It then calls
/// `0x080d3570(resource, mode)` and returns its status; every rejected state
/// returns zero after unlocking.
///
/// Deliberate deviations: the two callees have no ported ledger entries, so
/// their verified addresses remain one narrow operation seam rather than
/// receiving invented identities. The target seam calls the canonical ported
/// mutex functions instead of their 4-byte alias veneers at `0x082621a8` and
/// `0x082621ac`; host seams replace all external effects.
///
/// # Safety
///
/// `resource` must be valid for the class check and, when it is a 'plst'
/// element, readable through `+0x1ae`; successful gating also requires a
/// valid resource-pending object at `+0x0c` for the installed gate operation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.plst_resource_activate")]
pub unsafe extern "C" fn plst_resource_activate(resource: *mut u8, mode: u32) -> u32 {
    let ops = plst_resource_activate_ops();
    (ops.lock)(RESOURCE_MUTEX_ADDRESS as *mut PosixMutex);

    let result = if ui_element_is_plst_class(resource) != 0
        && resource.add(RESOURCE_FLAGS_OFFSET).read() & RESOURCE_ACTIVE_FLAG != 0
        && (resource.add(RESOURCE_STATE_OFFSET) as *const u32).read() == 0
        && (ops.gate)((resource.add(RESOURCE_PENDING_OFFSET) as *const u32).read() as usize as *mut u8, 0) == 0
        && resource.add(RESOURCE_MODE_OFFSET).read() == 1
    {
        (ops.activate)(resource, mode)
    } else {
        0
    };

    (ops.unlock)(RESOURCE_MUTEX_ADDRESS as *mut PosixMutex);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u8; 4] = [0; 4];
    static mut CALL_COUNT: usize = 0;
    static mut GATE_ARGUMENT: usize = 0;
    static mut ACTIVATE_ARGUMENTS: (usize, u32) = (0, 0);
    static mut GATE_RESULT: u32 = 0;
    static mut ACTIVATE_RESULT: u32 = 0;

    unsafe fn record(call: u8) {
        CALLS[CALL_COUNT] = call;
        CALL_COUNT += 1;
    }

    unsafe extern "C" fn lock(_mutex: *mut PosixMutex) { record(1); }
    unsafe extern "C" fn gate(resource: *mut u8, _mode: u32) -> u32 {
        GATE_ARGUMENT = resource as usize;
        record(2);
        GATE_RESULT
    }
    unsafe extern "C" fn activate(resource: *mut u8, mode: u32) -> u32 {
        ACTIVATE_ARGUMENTS = (resource as usize, mode);
        record(3);
        ACTIVATE_RESULT
    }
    unsafe extern "C" fn unlock(_mutex: *mut PosixMutex) { record(4); }

    struct OpsRestore;
    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(PLST_RESOURCE_ACTIVATE_OPS)
                    .write_volatile(DEFAULT_PLST_RESOURCE_ACTIVATE_OPS);
            }
        }
    }

    fn install_mocks(gate_result: u32, activate_result: u32) -> OpsRestore {
        unsafe {
            CALLS = [0; 4];
            CALL_COUNT = 0;
            GATE_ARGUMENT = 0;
            ACTIVATE_ARGUMENTS = (0, 0);
            GATE_RESULT = gate_result;
            ACTIVATE_RESULT = activate_result;
            ptr::addr_of_mut!(PLST_RESOURCE_ACTIVATE_OPS).write_volatile(PlstResourceActivateOps {
                lock,
                gate,
                activate,
                unlock,
            });
        }
        OpsRestore
    }

    fn active_plst_resource() -> [u8; RESOURCE_MODE_OFFSET + 1] {
        let mut resource = [0; RESOURCE_MODE_OFFSET + 1];
        resource[4..8].copy_from_slice(&0x706c_7374u32.to_ne_bytes());
        resource[RESOURCE_FLAGS_OFFSET] = RESOURCE_ACTIVE_FLAG;
        resource[RESOURCE_MODE_OFFSET] = 1;
        resource
    }

    #[test]
    fn null_resource_locks_then_returns_zero() {
        let _guard = TEST_LOCK.lock();
        let _restore = install_mocks(0, 99);
        assert_eq!(unsafe { plst_resource_activate(ptr::null_mut(), 7) }, 0);
        assert_eq!(unsafe { &CALLS[..CALL_COUNT] }, [1, 4]);
    }

    #[test]
    fn active_resource_calls_gate_with_pending_field_and_forwards_status() {
        let _guard = TEST_LOCK.lock();
        let _restore = install_mocks(0, 0x45);
        let mut resource = active_plst_resource();
        resource[RESOURCE_PENDING_OFFSET..RESOURCE_PENDING_OFFSET + 4]
            .copy_from_slice(&0x1122_3344u32.to_ne_bytes());

        assert_eq!(unsafe { plst_resource_activate(resource.as_mut_ptr(), 9) }, 0x45);
        assert_eq!(unsafe { &CALLS[..CALL_COUNT] }, [1, 2, 3, 4]);
        assert_eq!(unsafe { GATE_ARGUMENT }, 0x1122_3344);
        assert_eq!(unsafe { ACTIVATE_ARGUMENTS }, (resource.as_mut_ptr() as usize, 9));
    }

    #[test]
    fn gate_failure_skips_activation_but_unlocks() {
        let _guard = TEST_LOCK.lock();
        let _restore = install_mocks(1, 0x45);
        let mut resource = active_plst_resource();
        assert_eq!(unsafe { plst_resource_activate(resource.as_mut_ptr(), 0) }, 0);
        assert_eq!(unsafe { &CALLS[..CALL_COUNT] }, [1, 2, 4]);
    }

    #[test]
    fn pending_state_skips_gate() {
        let _guard = TEST_LOCK.lock();
        let _restore = install_mocks(0, 0x45);
        let mut resource = active_plst_resource();
        resource[RESOURCE_STATE_OFFSET..RESOURCE_STATE_OFFSET + 4]
            .copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(unsafe { plst_resource_activate(resource.as_mut_ptr(), 0) }, 0);
        assert_eq!(unsafe { &CALLS[..CALL_COUNT] }, [1, 4]);
    }
}
