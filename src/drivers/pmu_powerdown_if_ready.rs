//! `pmu_powerdown_if_ready` — original: `FUN_0836b1f0` @ **0x0836b1f0**
//! (**36 bytes**, `0x0836b1f0..0x0836b213`; the following literal at
//! `0x0836b214` supplies global base `0x089ca458`, and the next function
//! starts at `0x0836b218`). Raw A32 decoding finds one unconditional body
//! `bl` to veneer `0x080d3de4` (target `0x082e5b40`) and no predicated `bl`.
//!
//! # Algorithm
//!
//! If word `+4` of the PMU powerdown state at `0x089ca458` is zero, return
//! status 11. Otherwise invoke the established opaque powerdown transition
//! entry with the caller's word and return zero, discarding its return value.
//!
//! # Deliberate deviations
//!
//! The transition entry has no recovered identity beyond its verified address
//! and ABI. Target builds call that address; host builds inject a seam.

use core::ptr;

pub type PmuPowerdownTransition = unsafe extern "C" fn(u32);

const PMU_POWERDOWN_STATE_ADDRESS: *const u32 = 0x089c_a458usize as *const u32;
const PMU_POWERDOWN_TRANSITION_ADDRESS: usize = 0x080d_3de4;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_pmu_powerdown_transition(value: u32) {
    unsafe { core::mem::transmute::<usize, PmuPowerdownTransition>(PMU_POWERDOWN_TRANSITION_ADDRESS)(value) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pmu_powerdown_transition(_: u32) {
    panic!("pmu_powerdown_if_ready requires transition entry 0x080d3de4")
}

#[cfg(target_os = "none")]
pub static mut PMU_POWERDOWN_TRANSITION: PmuPowerdownTransition = retail_pmu_powerdown_transition;
#[cfg(not(target_os = "none"))]
pub static mut PMU_POWERDOWN_TRANSITION: PmuPowerdownTransition = missing_pmu_powerdown_transition;

#[cfg(not(target_os = "none"))]
static mut HOST_PMU_POWERDOWN_STATE: [u32; 2] = [0; 2];

#[inline(always)]
unsafe fn pmu_powerdown_state_ready() -> bool {
    #[cfg(target_os = "none")]
    {
        unsafe { ptr::read_volatile(PMU_POWERDOWN_STATE_ADDRESS.add(1)) != 0 }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(HOST_PMU_POWERDOWN_STATE[1])) != 0 }
    }
}

#[inline(always)]
fn pmu_powerdown_transition() -> PmuPowerdownTransition {
    unsafe { ptr::read_volatile(ptr::addr_of!(PMU_POWERDOWN_TRANSITION)) }
}

/// Requests PMU powerdown through the registered retail transition.
///
/// # Safety
///
/// On target, the fixed state address and transition entry must retain their
/// retailOS layouts and ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_powerdown_if_ready(value: u32) -> u32 {
    if !unsafe { pmu_powerdown_state_ready() } {
        return 11;
    }
    unsafe { pmu_powerdown_transition()(value) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static VALUE: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn record_transition(value: u32) {
        CALLS.fetch_add(1, Ordering::SeqCst);
        VALUE.store(value, Ordering::SeqCst);
    }

    #[test]
    fn returns_unavailable_without_calling_transition() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            HOST_PMU_POWERDOWN_STATE[1] = 0;
            PMU_POWERDOWN_TRANSITION = record_transition;
        }
        CALLS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { pmu_powerdown_if_ready(0xffff_ffff) }, 11);
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn forwards_any_word_when_powerdown_state_is_ready() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            HOST_PMU_POWERDOWN_STATE[1] = 0x8000_0000;
            PMU_POWERDOWN_TRANSITION = record_transition;
        }
        CALLS.store(0, Ordering::SeqCst);
        VALUE.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { pmu_powerdown_if_ready(0xdead_beef) }, 0);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(VALUE.load(Ordering::SeqCst), 0xdead_beef);
    }
}
