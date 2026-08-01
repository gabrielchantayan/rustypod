//! ARM CPSR interrupt-mask operations.

/// Mask used by CPSR's IRQ-disable (I) and FIQ-disable (F) bits.
const CPSR_IF_MASK: u32 = 0xc0;

/// cpsr_disable_irq_fiq — original: `FUN_08001e70` @ `0x08001e70` (20 bytes).
/// Reference: `ipod-decomp/decomp/osos.asm` @ `0x08001e70..0x08001e80`.
///
/// Snapshots CPSR, returns only its prior I/F mask, then sets both I/F bits
/// through `msr cpsr_c`. The target sequence is MRS/ORR/MSR exactly as in the
/// firmware. Host builds use a local simulated CPSR seam because they cannot
/// alter processor interrupt state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cpsr_disable_irq_fiq() -> u32 {
    #[cfg(target_os = "none")]
    {
        let saved_if_mask: u32;
        unsafe {
            core::arch::asm!(
                "mrs r1, cpsr",
                "and r0, r1, #0xc0",
                "orr r1, r1, #0xc0",
                "msr cpsr_c, r1",
                out("r0") saved_if_mask,
                out("r1") _,
                options(nostack, preserves_flags),
            );
        }
        saved_if_mask
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        host_cpsr::disable_interrupts()
    }
}
///
/// cpsr_restore_irq_fiq — original: `FUN_08001e84` @ `0x08001e84` (20 bytes).
/// Reference: `ipod-decomp/decomp/osos.asm` @ `0x08001e84..0x08001e94`.
///
/// Reads CPSR, clears its IRQ/FIQ I/F bits, merges the saved I/F mask, and
/// writes the CPSR control field. Target builds retain the firmware's exact
/// MRS/BIC/ORR/MSR sequence; host builds use the deterministic CPSR seam and
/// constrain the saved value to the I/F mask.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cpsr_restore_irq_fiq(saved_if_mask: u32) {
    #[cfg(target_os = "none")]
    unsafe {
        core::arch::asm!(
            "mrs r1, cpsr",
            "bic r1, r1, #0xc0",
            "orr r0, r1, r0",
            "msr cpsr_c, r0",
            inout("r0") saved_if_mask => _,
            out("r1") _,
            options(nostack, preserves_flags),
        );
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        host_cpsr::restore_interrupts(saved_if_mask);
    }
}

/// Deterministic local CPSR seam for host behavioral tests.
#[cfg(not(target_os = "none"))]
mod host_cpsr {
    use core::ptr::{addr_of, addr_of_mut};

    pub(super) static mut CPSR: u32 = 0;

    #[inline(always)]
    pub(super) unsafe fn disable_interrupts() -> u32 {
        let cpsr = core::ptr::read_volatile(addr_of!(CPSR));
        // `msr cpsr_c` writes only the low control byte; the sequence keeps
        // every pre-existing control bit and sets I/F within that byte.
        let updated = (cpsr & !0xff) | ((cpsr | super::CPSR_IF_MASK) & 0xff);
        core::ptr::write_volatile(addr_of_mut!(CPSR), updated);
        cpsr & super::CPSR_IF_MASK
    }

    #[inline(always)]
    pub(super) unsafe fn restore_interrupts(saved_if_mask: u32) {
        let cpsr = core::ptr::read_volatile(addr_of!(CPSR));
        let updated = (cpsr & !super::CPSR_IF_MASK) | (saved_if_mask & super::CPSR_IF_MASK);
        core::ptr::write_volatile(addr_of_mut!(CPSR), updated);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn returns_prior_if_mask_and_sets_both_mask_bits() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());

        for cpsr in [0x0000_0013, 0x6000_0053, 0xa000_0093, 0xf000_00d3] {
            unsafe {
                core::ptr::write_volatile(addr_of_mut!(host_cpsr::CPSR), cpsr);
                assert_eq!(cpsr_disable_irq_fiq(), cpsr & CPSR_IF_MASK);
                assert_eq!(
                    core::ptr::read_volatile(addr_of!(host_cpsr::CPSR)),
                    cpsr | CPSR_IF_MASK,
                    "CPSR transition for {cpsr:#010x}",
                );
            }
        }
    }

    #[test]
    fn restores_each_saved_mask_without_changing_other_cpsr_bits() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        const CURRENT_CPSR: u32 = 0xa5a5_00d3;

        for saved_if_mask in [0, CPSR_IF_MASK] {
            unsafe {
                core::ptr::write_volatile(addr_of_mut!(host_cpsr::CPSR), CURRENT_CPSR);
                cpsr_restore_irq_fiq(saved_if_mask);
                let restored = core::ptr::read_volatile(addr_of!(host_cpsr::CPSR));
                assert_eq!(restored & CPSR_IF_MASK, saved_if_mask);
                assert_eq!(
                    restored & !CPSR_IF_MASK,
                    CURRENT_CPSR & !CPSR_IF_MASK,
                    "non-I/F CPSR bits for saved mask {saved_if_mask:#04x}",
                );
            }
        }
    }
}
