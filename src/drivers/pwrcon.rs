//! PWRCON clock-gate mask updates for the S5L8702.
//!
//! `PWRCON0` and `PWRCON1` live at `0x3c50_0048` and `0x3c50_004c`.
//! Their gate bits are active-low: clearing a selected bit enables its clock.

const PWRCON0: *mut u32 = 0x3c50_0048 as *mut u32;
const PWRCON1: *mut u32 = 0x3c50_004c as *mut u32;
const CPSR_IF_MASK: u32 = 0xc0;

/// Disables IRQ and FIQ and returns their prior CPSR mask, matching
/// `FUN_08001e70` exactly.
#[cfg(target_os = "none")]
#[inline(never)]
unsafe fn critical_section_enter() -> u32 {
    let cpsr: u32;
    unsafe {
        core::arch::asm!(
            "mrs {cpsr}, cpsr",
            "orr {masked}, {cpsr}, #0xc0",
            "msr cpsr_c, {masked}",
            cpsr = out(reg) cpsr,
            masked = lateout(reg) _,
            options(nostack),
        );
    }
    cpsr & CPSR_IF_MASK
}

/// Restores only the prior IRQ/FIQ CPSR bits, matching `FUN_08001e84`.
#[cfg(target_os = "none")]
#[inline(never)]
unsafe fn critical_section_exit(saved_if_mask: u32) {
    
    unsafe {
        core::arch::asm!(
            "mrs {cpsr}, cpsr",
            "bic {cpsr}, {cpsr}, #0xc0",
            "orr {cpsr}, {cpsr}, {saved_if_mask}",
            "msr cpsr_c, {cpsr}",
            cpsr = inout(reg) 0u32 => _,
            saved_if_mask = in(reg) saved_if_mask,
            options(nostack),
        );
    }
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostPwrconOps {
    enter: unsafe extern "C" fn() -> u32,
    read_pwrcon0: unsafe extern "C" fn() -> u32,
    write_pwrcon0: unsafe extern "C" fn(u32),
    read_pwrcon1: unsafe extern "C" fn() -> u32,
    write_pwrcon1: unsafe extern "C" fn(u32),
    exit: unsafe extern "C" fn(u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_seam_uninstalled() -> u32 {
    panic!("install PWRCON host operations before calling pwrcon_update_masks")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_write_seam_uninstalled(_: u32) {
    panic!("install PWRCON host operations before calling pwrcon_update_masks")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_exit_seam_uninstalled(_: u32) {
    panic!("install PWRCON host operations before calling pwrcon_update_masks")
}

/// Replaceable host-only PWRCON and CPSR boundary. Tests install recorders so
/// they can prove the critical-section ordering without fabricating MMIO.
#[cfg(not(target_os = "none"))]
static mut HOST_PWRCON_OPS: HostPwrconOps = HostPwrconOps {
    enter: host_seam_uninstalled,
    read_pwrcon0: host_seam_uninstalled,
    write_pwrcon0: host_write_seam_uninstalled,
    read_pwrcon1: host_seam_uninstalled,
    write_pwrcon1: host_write_seam_uninstalled,
    exit: host_exit_seam_uninstalled,
};

/// pwrcon_update_masks — original: `FUN_08000318` @ `0x08000318` (72 bytes).
/// Reference: `ipod-decomp/decomp/c/000/08000318_FUN_08000318.c` and
/// `decomp/osos.asm` @ `0x08000318..0x0800035c`.
///
/// Enters the IRQ/FIQ guard, updates the selected masks in `PWRCON0` and
/// `PWRCON1`, then restores the saved guard state and returns zero. A zero
/// `enable` argument sets each selected bit (gates clocks); every nonzero
/// value clears each selected bit (enables clocks). The target path performs
/// the original volatile MMIO reads/writes and preserves the enter/write/exit
/// order. The host path deliberately substitutes only those boundaries with a
/// driver-local seam for behavioral tests.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pwrcon_update_masks(
    pwrcon0_mask: u32,
    pwrcon1_mask: u32,
    enable: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        let saved_if_mask = critical_section_enter();
        let pwrcon0 = core::ptr::read_volatile(PWRCON0);
        let pwrcon0 = if enable == 0 {
            pwrcon0 | pwrcon0_mask
        } else {
            pwrcon0 & !pwrcon0_mask
        };
        core::ptr::write_volatile(PWRCON0, pwrcon0);

        let pwrcon1 = core::ptr::read_volatile(PWRCON1);
        let pwrcon1 = if enable == 0 {
            pwrcon1 | pwrcon1_mask
        } else {
            pwrcon1 & !pwrcon1_mask
        };
        core::ptr::write_volatile(PWRCON1, pwrcon1);
        critical_section_exit(saved_if_mask);
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(HOST_PWRCON_OPS));
        let saved_if_mask = (ops.enter)();
        let pwrcon0 = (ops.read_pwrcon0)();
        (ops.write_pwrcon0)(if enable == 0 {
            pwrcon0 | pwrcon0_mask
        } else {
            pwrcon0 & !pwrcon0_mask
        });
        let pwrcon1 = (ops.read_pwrcon1)();
        (ops.write_pwrcon1)(if enable == 0 {
            pwrcon1 | pwrcon1_mask
        } else {
            pwrcon1 & !pwrcon1_mask
        });
        (ops.exit)(saved_if_mask);
    }

    0
}

/// iram_pwrcon_update_masks_veneer — original: `thunk_EXT_FUN_22000318` @
/// 0x08037de8 (Ghidra reports 4 bytes; the real stub is **8** — the
/// `ldr pc, [pc, #-4]` word 0xe51ff004 at 0x08037de8 plus the absolute
/// target word 0x22000318 at 0x08037dec, binary-decoded from osos.dec).
///
/// **31 `bl` call sites, all unconditional, plus 3 tail `b`
/// (0x080923b4 / 0x080ce0c4 / 0x0836d8c4) and 1 `beq` (0x0836e0a0)**,
/// counted by decoding every ARM `B`/`BL` word in
/// `work/firmware/osos.dec` for every condition code and resolving its
/// target — not a Ghidra xref count. No DATA word holds the thunk
/// address, so it is not virtually dispatched. The predicated `beq` is a
/// caller-side branch choice, not a NULL guard on this callee — the
/// veneer and its target take pointer-less mask arguments.
///
/// # The target resolves to the already-ported [`pwrcon_update_masks`]
///
/// 0x22000000 is S5L8702 internal SRAM, populated from the osos image
/// itself: the relocator @ 0x080046e0 memmoves 0xaed8 bytes from
/// 0x08000000 to 0x22000000 (see `libc/iram_veneers.rs` for the full
/// three-fact argument pinning that mirror). So IRAM 0x22000318 is osos
/// 0x08000318, which is [`pwrcon_update_masks`] @ 0x08000318 — the
/// IRQ/FIQ-guarded PWRCON0/PWRCON1 read-modify-write above. This veneer
/// therefore forwards to it directly rather than re-stubbing it.
/// (kernel/thunks.rs's ROM_THUNKS registry lists the 0x08037de8 ->
/// 0x22000318 pair with name None; the name is recorded here per the
/// iram_usec_timer_read_veneer precedent.)
///
/// # What the veneer does
///
/// Nothing but transfer control: r0/r1/r2 pass through untouched, no
/// stack is used, `lr` still points at the caller, so it is exactly a
/// tail call returning the body's r0 (always 0). The callee is loaded
/// through `read_volatile`: written as a plain call LLVM could inline
/// the body, and its identical-function folding could collapse the
/// veneer onto another call of the same shape — destroying the separate
/// 0x08037de8 hook seam that is this port's entire purpose. The distinct
/// `link_section` guards the same invariant at link time.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iram_pwrcon_update_masks_veneer")]
#[inline(never)]
pub unsafe extern "C" fn iram_pwrcon_update_masks_veneer(
    pwrcon0_mask: u32,
    pwrcon1_mask: u32,
    enable: u32,
) -> u32 {
    let body = core::ptr::read_volatile(
        &(pwrcon_update_masks as unsafe extern "C" fn(u32, u32, u32) -> u32),
    );
    body(pwrcon0_mask, pwrcon1_mask, enable)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut TEST_PWRCON0: u32 = 0;
    static mut TEST_PWRCON1: u32 = 0;
    static mut SAVED_IF_MASK: u32 = 0;
    static mut CALL_LOG: Vec<&'static str> = Vec::new();

    unsafe extern "C" fn enter() -> u32 {
        unsafe {
            (*addr_of_mut!(CALL_LOG)).push("enter");
        }
        0x80
    }

    unsafe extern "C" fn read_pwrcon0() -> u32 {
        unsafe {
            (*addr_of_mut!(CALL_LOG)).push("read0");
            *addr_of!(TEST_PWRCON0)
        }
    }

    unsafe extern "C" fn write_pwrcon0(value: u32) {
        unsafe {
            (*addr_of_mut!(CALL_LOG)).push("write0");
            *addr_of_mut!(TEST_PWRCON0) = value;
        }
    }

    unsafe extern "C" fn read_pwrcon1() -> u32 {
        unsafe {
            (*addr_of_mut!(CALL_LOG)).push("read1");
            *addr_of!(TEST_PWRCON1)
        }
    }

    unsafe extern "C" fn write_pwrcon1(value: u32) {
        unsafe {
            (*addr_of_mut!(CALL_LOG)).push("write1");
            *addr_of_mut!(TEST_PWRCON1) = value;
        }
    }

    unsafe extern "C" fn exit(saved: u32) {
        unsafe {
            (*addr_of_mut!(CALL_LOG)).push("exit");
            *addr_of_mut!(SAVED_IF_MASK) = saved;
        }
    }

    struct HostOpsReset {
        saved: HostPwrconOps,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(HOST_PWRCON_OPS).write(self.saved);
            }
        }
    }

    fn install(pwrcon0: u32, pwrcon1: u32) -> HostOpsReset {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(addr_of!(HOST_PWRCON_OPS));
            *addr_of_mut!(TEST_PWRCON0) = pwrcon0;
            *addr_of_mut!(TEST_PWRCON1) = pwrcon1;
            *addr_of_mut!(SAVED_IF_MASK) = 0;
            (*addr_of_mut!(CALL_LOG)).clear();
            addr_of_mut!(HOST_PWRCON_OPS).write(HostPwrconOps {
                enter,
                read_pwrcon0,
                write_pwrcon0,
                read_pwrcon1,
                write_pwrcon1,
                exit,
            });
            HostOpsReset {
                saved,
                _lock: lock,
            }
        }
    }

    #[test]
    fn zero_enable_sets_selected_bits_in_both_pwrcon_words() {
        let _ops = install(0x1200_0001, 0x00a0_0002);
        unsafe {
            assert_eq!(pwrcon_update_masks(0x0000_0c20, 0x8000_1004, 0), 0);
            assert_eq!(*addr_of!(TEST_PWRCON0), 0x1200_0c21, "PWRCON0 sets its mask");
            assert_eq!(*addr_of!(TEST_PWRCON1), 0x80a0_1006, "PWRCON1 sets its mask");
        }
    }

    #[test]
    fn nonzero_enable_clears_selected_bits_in_both_pwrcon_words() {
        let _ops = install(0xf00f_0f0f, 0xffff_1234);
        unsafe {
            assert_eq!(pwrcon_update_masks(0x000f_0c03, 0xf000_1034, 2), 0);
            assert_eq!(*addr_of!(TEST_PWRCON0), 0xf000_030c, "PWRCON0 clears its mask");
            assert_eq!(*addr_of!(TEST_PWRCON1), 0x0fff_0200, "PWRCON1 clears its mask");
        }
    }

    #[test]
    fn guard_brackets_reads_and_writes_and_receives_the_saved_mask() {
        let _ops = install(0, 0);
        unsafe {
            pwrcon_update_masks(1, 2, 0);
            assert_eq!(*addr_of!(SAVED_IF_MASK), 0x80, "exit receives enter's saved I/F bits");
            assert_eq!(
                *addr_of!(CALL_LOG),
                ["enter", "read0", "write0", "read1", "write1", "exit"],
                "the two volatile read-modify-writes remain inside the guard",
            );
        }
    }

    /// The IRAM veneer @ 0x08037de8 must be behaviorally transparent on
    /// the gate path: the same guarded set-mask transaction the body @
    /// 0x08000318 performs, and the same r0 result (always 0).
    #[test]
    fn iram_veneer_forwards_the_set_masks_transaction() {
        let _ops = install(0x1200_0001, 0x00a0_0002);
        unsafe {
            assert_eq!(iram_pwrcon_update_masks_veneer(0x0000_0c20, 0x8000_1004, 0), 0);
            assert_eq!(*addr_of!(TEST_PWRCON0), 0x1200_0c21, "PWRCON0 sets its mask");
            assert_eq!(*addr_of!(TEST_PWRCON1), 0x80a0_1006, "PWRCON1 sets its mask");
            assert_eq!(
                *addr_of!(CALL_LOG),
                ["enter", "read0", "write0", "read1", "write1", "exit"],
                "exactly one guarded transaction per veneer call",
            );
        }
    }

    /// The clear path (enable != 0) must pass `enable` through verbatim —
    /// any nonzero value clears the masks, matching the original's
    /// `cmp r6, #0` / orreq / bicne predication.
    #[test]
    fn iram_veneer_forwards_the_clear_masks_transaction() {
        let _ops = install(0xf00f_0f0f, 0xffff_1234);
        unsafe {
            assert_eq!(iram_pwrcon_update_masks_veneer(0x000f_0c03, 0xf000_1034, 2), 0);
            assert_eq!(*addr_of!(TEST_PWRCON0), 0xf000_030c, "PWRCON0 clears its mask");
            assert_eq!(*addr_of!(TEST_PWRCON1), 0x0fff_0200, "PWRCON1 clears its mask");
        }
    }

    /// The whole point of the port is that a hook at 0x08037de8 lands on
    /// a forwarding stub distinct from the body at 0x08000318. Identical
    /// bodies are exactly what LLVM's identical-function folding
    /// collapses, so assert the two symbols stay apart.
    #[test]
    fn iram_veneer_is_a_distinct_call_target_from_its_body() {
        let (veneer, body) = unsafe {
            (
                core::ptr::read_volatile(
                    &(iram_pwrcon_update_masks_veneer as unsafe extern "C" fn(u32, u32, u32) -> u32),
                ),
                core::ptr::read_volatile(
                    &(pwrcon_update_masks as unsafe extern "C" fn(u32, u32, u32) -> u32),
                ),
            )
        };
        assert_ne!(veneer as usize, 0);
        assert_ne!(veneer as usize, body as usize);
    }
}
