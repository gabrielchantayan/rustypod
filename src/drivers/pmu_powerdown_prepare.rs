//! PMU powerdown preparation transaction.

use crate::drivers::pwrcon::{pwrcon_acquire_clock_2, pwrcon_restore_clock_2};

const PMU_POWERDOWN_STATE: *const u32 = 0x089c_a458 as *const u32;
const PMU_POWERDOWN_READY_WORD: usize = 1;
#[cfg(target_os = "none")]
const PMU_POWERDOWN_CONFIGURE_ADDRESS: usize = 0x080d_4ad8;
#[cfg(target_os = "none")]
const PMU_POWERDOWN_INITIALIZE_ADDRESS: usize = 0x080c_9998;

#[cfg(target_os = "none")]
unsafe fn pmu_powerdown_configure() {
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn()>(PMU_POWERDOWN_CONFIGURE_ADDRESS)() }
}

#[cfg(target_os = "none")]
unsafe fn pmu_powerdown_initialize() {
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn()>(PMU_POWERDOWN_INITIALIZE_ADDRESS)() }
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostPmuPowerdownOps {
    acquire_clock: unsafe extern "C" fn() -> u32,
    configure_state: unsafe extern "C" fn(),
    initialize_state: unsafe extern "C" fn(),
    read_state_ready: unsafe extern "C" fn() -> u32,
    restore_clock: unsafe extern "C" fn(u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_seam_uninstalled() -> u32 {
    panic!("install PMU-powerdown host operations before calling pmu_powerdown_prepare")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_void_seam_uninstalled() {
    panic!("install PMU-powerdown host operations before calling pmu_powerdown_prepare")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_restore_seam_uninstalled(_: u32) -> u32 {
    panic!("install PMU-powerdown host operations before calling pmu_powerdown_prepare")
}

#[cfg(not(target_os = "none"))]
static mut HOST_PMU_POWERDOWN_OPS: HostPmuPowerdownOps = HostPmuPowerdownOps {
    acquire_clock: host_seam_uninstalled,
    configure_state: host_void_seam_uninstalled,
    initialize_state: host_void_seam_uninstalled,
    read_state_ready: host_seam_uninstalled,
    restore_clock: host_restore_seam_uninstalled,
};

/// pmu_powerdown_prepare — original: `FUN_0836b1b4` @ `0x0836b1b4`.
///
/// Raw decoding establishes the 56-byte extent `0x0836b1b4..0x0836b1ec`;
/// `0x0836b1ec` is its literal pool and the next real function starts at
/// `0x0836b1f0`. It has four unconditional direct `bl` instructions
/// (`0x0836b1bc`, `0x0836b1c4`, `0x0836b1c8`, and `0x0836b1e0`) and no
/// predicated `bl` instructions. The first and last calls use the existing
/// clock-2 ports.
///
/// Acquires clock 2, prepares PMU powerdown state, then returns 20 if the
/// state's word at offset 4 is still null; it always restores the saved clock
/// state. The two middle direct callees have no established names in
/// `names.yaml`, so the target build deliberately retains calls through their
/// verified raw addresses rather than assigning identities. Host builds
/// replace those raw boundaries and the global read with recording seams.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pmu_powerdown_prepare() -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        let was_enabled = pwrcon_acquire_clock_2();
        pmu_powerdown_configure();
        pmu_powerdown_initialize();
        let result = if core::ptr::read(PMU_POWERDOWN_STATE.add(PMU_POWERDOWN_READY_WORD)) == 0 { 20 } else { 0 };
        pwrcon_restore_clock_2(was_enabled);
        result
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(HOST_PMU_POWERDOWN_OPS));
        let was_enabled = (ops.acquire_clock)();
        (ops.configure_state)();
        (ops.initialize_state)();
        let result = if (ops.read_state_ready)() == 0 { 20 } else { 0 };
        (ops.restore_clock)(was_enabled);
        result
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<std::vec::Vec<u32>> = Mutex::new(std::vec::Vec::new());
    static mut STATE_READY: u32 = 0;

    unsafe extern "C" fn acquire_clock() -> u32 {
        EVENTS.lock().push(1);
        0xa5
    }

    unsafe extern "C" fn configure_state() {
        EVENTS.lock().push(2);
    }

    unsafe extern "C" fn initialize_state() {
        EVENTS.lock().push(3);
    }

    unsafe extern "C" fn read_state_ready() -> u32 {
        EVENTS.lock().push(4);
        unsafe { STATE_READY }
    }

    unsafe extern "C" fn restore_clock(was_enabled: u32) -> u32 {
        EVENTS.lock().push(was_enabled);
        0
    }

    unsafe fn install(state_ready: u32) {
        EVENTS.lock().clear();
        STATE_READY = state_ready;
        HOST_PMU_POWERDOWN_OPS = HostPmuPowerdownOps {
            acquire_clock,
            configure_state,
            initialize_state,
            read_state_ready,
            restore_clock,
        };
    }

    #[test]
    fn prepare_reports_missing_state_after_initialization_and_restores_clock() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            install(0);
            assert_eq!(pmu_powerdown_prepare(), 20);
        }
        assert_eq!(*EVENTS.lock(), [1, 2, 3, 4, 0xa5]);
    }

    #[test]
    fn prepare_reports_ready_state_and_restores_clock() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            install(1);
            assert_eq!(pmu_powerdown_prepare(), 0);
        }
        assert_eq!(*EVENTS.lock(), [1, 2, 3, 4, 0xa5]);
    }
}
