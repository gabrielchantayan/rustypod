//! PMU feedback status refresh — retail `FUN_0809e4d0` at `0x0809e4d0`.
//! 116 instruction bytes, 128-byte extent including three literals; next
//! function starts at `0x0809e550`. Raw ARM words verify three plain outbound
//! BLs, zero predicated BLs, one BLXNE callback; inbound: one BL and one BLEQ.
//!
//! Read the board PMU bit then register 0x4b bit 2. Publish one iff either
//! bit and the enable word are nonzero, apply the inverse feedback mode,
//! then notify event 15 with a fresh snapshot of the published word.
//!
//! Deliberate deviations: retain the two retail PMU wrappers in a single ARM
//! assembly island rather than substitute their Rust ports: the second read
//! inherits the first call's scratch registers on failed I2C transfers.
//! The island uses literal-address BLX calls in place of BL; r12 is
//! caller-scratch and neither wrapper consumes its incoming value.
//! The feedback mode call uses its existing Rust port. Host tests exercise
//! the state transition with injected read results, not hardware I2C.

use core::ptr;

type StatusCallback = unsafe extern "C" fn(u32, *mut u32);

unsafe fn publish_status(
    board_bit: u32,
    register_bit: u32,
    enable: *const u32,
    published: *mut u32,
    apply: impl FnOnce(u32),
    callback: impl FnOnce() -> Option<StatusCallback>,
) {
    let active = (board_bit | register_bit) != 0
        && ptr::read_volatile(enable) != 0;
    ptr::write_volatile(published, active as u32);
    apply(1 - active as u32);
    let mut snapshot = ptr::read_volatile(published);
    if let Some(notify) = callback() {
        notify(15, &mut snapshot);
    }
}

/// # Safety
/// Requires the retail PMU code, fixed globals, and callback ABI to be live.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_feedback_status_refresh(
    _unused: u32, incoming_r1: u32, incoming_r2: u32, incoming_r3: u32,
) {
    #[cfg(target_os = "none")]
    {
        let board_bit: u32;
        let register_bit: u32;
        core::arch::asm!(
            "push {{r1, r2, r3, lr}}",
            "add r0, sp, #8",
            "ldr r12, =0x080c8890",
            "blx r12",
            "add r0, sp, #4",
            "ldr r12, =0x080bfbd4",
            "blx r12",
            "ldr r0, [sp, #8]",
            "ldr r1, [sp, #4]",
            "add sp, sp, #16",
            lateout("r0") board_bit,
            inlateout("r1") incoming_r1 => register_bit,
            in("r2") incoming_r2,
            in("r3") incoming_r3,
            clobber_abi("C"),
        );
        publish_status(board_bit, register_bit,
            0x089c_a98cusize as *const u32,
            0x089c_a980usize as *mut u32,
            |mode| { crate::app::feedback_level_mode_set::feedback_level_mode_set(mode); },
            || {
                let address = ptr::read_volatile(0x089c_a5e4usize as *const u32);
                if address == 0 { None } else { Some(core::mem::transmute::<usize, StatusCallback>(address as usize)) }
            });
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (incoming_r1, incoming_r2, incoming_r3);
        panic!("pmu_feedback_status_refresh requires retail PMU hardware");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static SNAPSHOT: AtomicU32 = AtomicU32::new(0);
    unsafe extern "C" fn notify(event: u32, value: *mut u32) {
        assert_eq!(event, 15);
        SNAPSHOT.store(*value, Ordering::SeqCst);
        *value = 99;
    }

    #[test]
    fn status_truth_table_and_inverse_mode() {
        for board in [0, 1, 0x8000_0000] {
            for register in [0, 1, u32::MAX] {
                for enable in [0, 1, u32::MAX] {
                    let mut published = 42;
                    let expected = ((board != 0 || register != 0) && enable != 0) as u32;
                    unsafe { publish_status(board, register, &enable, &mut published,
                        |mode| assert_eq!(mode, 1 - expected), || None); }
                    assert_eq!(published, expected);
                }
            }
        }
        // Retail must not read the enable word when both PMU bits are clear.
        let mut published = 42;
        unsafe { publish_status(0, 0, ptr::null(), &mut published,
            |mode| assert_eq!(mode, 1), || None); }
        assert_eq!(published, 0);
    }

    #[test]
    fn notification_reloads_state_after_mode_application_and_uses_local_copy() {
        let enable = 1;
        let mut published = 42;
        let address = ptr::addr_of_mut!(published);
        unsafe { publish_status(1, 0, &enable, address,
            |mode| {
                assert_eq!(mode, 0);
                assert_eq!(ptr::read_volatile(address), 1);
                ptr::write_volatile(address, 0xdead_beef);
            }, || Some(notify)); }
        assert_eq!(SNAPSHOT.load(Ordering::SeqCst), 0xdead_beef);
        assert_eq!(published, 0xdead_beef);
    }
}
