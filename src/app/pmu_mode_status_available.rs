//! `pmu_mode_status_available` — original: `FUN_080b4eb4` @ **0x080b4eb4**.
//!
//! Raw `osos.dec` words establish the 80-byte body `0x080b4eb4..0x080b4f03`;
//! the literal-pool word at `0x080b4f04` follows it. The body contains **3
//! plain, unconditional `bl` calls** (at `0x080b4ebc`, `0x080b4ec4`, and
//! `0x080b4ec8`) and no predicated calls. It stores PMU register 0x4b bit 2,
//! samples the board-selected PMU status bit, reads the code-generator mode
//! limit, and rejects a nonzero availability-blocked field at `0x089ca980`.
//! It otherwise accepts when register 0x4b bit 2 is set, or when the
//! board-selected bit is set and the signed mode limit is above 4.
//!
//! Deliberate deviations: the target reads the fixed availability-blocked
//! field directly; host builds use isolated storage for tests. The three
//! verified retail callees are already-ported Rust functions, so their direct
//! `bl` edges become Rust calls. The otherwise-undeclared incoming r0-r3 ABI
//! words are retained because incoming r3 reaches both PMU scratch-byte paths.

#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::codegen::mode_limit::cg_mode_limit;
use crate::drivers::pmu::{pmu_board_version_status_bit, store_pmu_register_0x4b_bit2};

#[cfg(not(target_os = "none"))]
static mut HOST_PMU_MODE_AVAILABILITY_BLOCKED: i32 = 0;

#[inline]
unsafe fn pmu_mode_availability_blocked() -> i32 {
    #[cfg(target_os = "none")]
    { core::ptr::read_volatile(0x089c_a980 as *const i32) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(HOST_PMU_MODE_AVAILABILITY_BLOCKED)) }
}

/// Returns whether the PMU and code-generator mode state permits availability.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_mode_status_available(
    _incoming_r0: u32,
    incoming_r1: u32,
    incoming_r2: u32,
    incoming_r3: u32,
) -> u32 {
    let mut register_0x4b_bit2 = incoming_r3;
    store_pmu_register_0x4b_bit2(
        &mut register_0x4b_bit2,
        incoming_r1,
        incoming_r2,
        incoming_r3,
    );
    let board_status_bit = pmu_board_version_status_bit(
        0,
        incoming_r1,
        incoming_r2,
        incoming_r3,
    );
    let mode_limit = cg_mode_limit();

    if pmu_mode_availability_blocked() != 0 {
        0
    } else if register_0x4b_bit2 != 0 || (board_status_bit != 0 && mode_limit > 4) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::mode_limit::CG_MODE_LIMIT_CACHE;
    use crate::drivers::i2c::tests::install_raw_i2c_for_test;
    use crate::sysinfo::install_host_cached_board_version;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    struct Fixture {
        _lock: parking_lot::MutexGuard<'static, ()>,
        previous_blocked: i32,
        previous_mode_limit: i8,
    }

    impl Fixture {
        unsafe fn install(blocked: i32, mode_limit: i8) -> Self {
            let lock = LOCK.lock();
            let previous_blocked = HOST_PMU_MODE_AVAILABILITY_BLOCKED;
            let previous_mode_limit = CG_MODE_LIMIT_CACHE;
            HOST_PMU_MODE_AVAILABILITY_BLOCKED = blocked;
            CG_MODE_LIMIT_CACHE = mode_limit;
            Self { _lock: lock, previous_blocked, previous_mode_limit }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                HOST_PMU_MODE_AVAILABILITY_BLOCKED = self.previous_blocked;
                CG_MODE_LIMIT_CACHE = self.previous_mode_limit;
            }
        }
    }

    #[test]
    fn register_0x4b_bit_two_allows_availability_regardless_of_mode_limit() {
        let _fixture = unsafe { Fixture::install(0, 4) };
        let _board = install_host_cached_board_version(0x0011_0000);
        let _i2c = install_raw_i2c_for_test(0, 0, 4);

        assert_eq!(unsafe { pmu_mode_status_available(0, 0, 0, 0) }, 1);
    }

    #[test]
    fn board_status_requires_a_mode_limit_strictly_above_four() {
        let _fixture = unsafe { Fixture::install(0, 5) };
        let _board = install_host_cached_board_version(0x0011_0000);
        let _i2c = install_raw_i2c_for_test(0, 0, 1);
        assert_eq!(unsafe { pmu_mode_status_available(0, 0, 0, 0) }, 1);
        drop(_i2c);

        unsafe { CG_MODE_LIMIT_CACHE = 4; }
        let _i2c = install_raw_i2c_for_test(0, 0, 1);
        assert_eq!(unsafe { pmu_mode_status_available(0, 0, 0, 0) }, 0);
    }

    #[test]
    fn availability_blocked_overrides_both_pmu_status_bits() {
        let _fixture = unsafe { Fixture::install(1, 0) };
        let _board = install_host_cached_board_version(0x0011_0000);
        let _i2c = install_raw_i2c_for_test(0, 0, 5);

        assert_eq!(unsafe { pmu_mode_status_available(0, 0, 0, 0) }, 0);
    }
}
