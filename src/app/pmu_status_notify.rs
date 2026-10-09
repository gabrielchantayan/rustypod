//! PMU-gated timestamp and mailbox notification.
//!
//! Original: FUN_080e3698 @ 0x080e3698. True size: 84 bytes (80 bytes of
//! instructions and the literal at 0x080e36e8); next function: 0x080e36ec.
//! Raw ARM decoding finds 2 plain inbound BLs, no predicated inbound BLs,
//! 5 plain outgoing BLs, 1 BLNE, and a tail B to mailbox_slot_post.
//!
//! Return immediately if register 0x4b bit 2 or the board-selected status
//! bit is set. Otherwise read register 0x19 bit 0, conditionally write one
//! to register 0x0c, then, if register 0x18 bit 0 is set, save the timer
//! word at global +8 and post the mailbox slot pointed to by global +4.
//!
//! Deliberate deviations: retain the first two already-identified retail
//! checks as one inline-assembly ABI boundary: the second consumes the first
//! call's outgoing r3 as its failed-I2C scratch byte. Ordinary Rust calls to
//! the existing ports cannot preserve that caller-clobbered register state.
//! The unported register-0x19 check is a typed fixed-address boundary; the
//! write, timer veneer and mailbox post reuse existing Rust ports. No PMU
//! hardware role beyond the verified register bits is assumed.

use crate::drivers::pmu::{pmu_register_0x18_bit0, pmu_write_register_0x0c_one};
use crate::drivers::timer::iram_usec_timer_read_veneer;
use crate::kernel::kobj::{mailbox_slot_post, Mailbox};

#[repr(C)]
struct NotificationState {
    flags: u32,
    mailbox_slot: *mut *mut Mailbox,
    timestamp: u32,
}

#[cfg(target_os = "none")]
unsafe fn status_blocks_notification(mut r0: u32, r1: u32, r2: u32, r3: u32) -> u32 {
    core::arch::asm!(
        "blx r4",
        "cmp r0, #0",
        "bne 2f",
        "blx r5",
        "2:",
        in("r4") 0x082e_53d8_u32,
        in("r5") 0x082e_5b64_u32,
        inout("r0") r0,
        inout("r1") r1 => _,
        inout("r2") r2 => _,
        inout("r3") r3 => _,
        lateout("r12") _,
        lateout("lr") _,
    );
    r0
}

#[cfg(not(target_os = "none"))]
unsafe fn status_blocks_notification(_r0: u32, _r1: u32, _r2: u32, _r3: u32) -> u32 {
    panic!("PMU notification requires the retail r0-r3 status-check boundary")
}

unsafe fn register_0x19_bit0() -> u32 {
    #[cfg(target_os = "none")]
    {
        let read: unsafe extern "C" fn() -> u32 = core::mem::transmute(0x082e_5430_usize);
        read()
    }
    #[cfg(not(target_os = "none"))]
    panic!("PMU notification requires retail register reader 0x082e5430")
}

#[inline(always)]
fn notify_if_ready(
    state: &mut NotificationState,
    blocked: u32,
    mut read_19: impl FnMut() -> u32,
    mut write_0c: impl FnMut(),
    mut read_18: impl FnMut() -> u32,
    mut timer: impl FnMut() -> u32,
    mut post: impl FnMut(*mut *mut Mailbox, u32),
) {
    if blocked != 0 { return; }
    if read_19() != 0 { write_0c(); }
    if read_18() == 0 { return; }
    state.timestamp = timer();
    post(state.mailbox_slot, state.timestamp);
}

/// PMU-gated notification @ 0x080e3698; see the module header for raw
/// extent, call counts, algorithm and ABI deviations.
///
/// # Safety
/// Firmware state at 0x089ca960 and its mailbox slot must be initialized;
/// the retail PMU and timer services must be available. Incoming ABI words
/// are explicit because the first PMU read saves incoming r3 on I2C failure.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_status_notify(r0: u32, r1: u32, r2: u32, r3: u32) {
    let blocked = status_blocks_notification(r0, r1, r2, r3);
    if blocked != 0 { return; }
    let state = &mut *(0x089c_a960_usize as *mut NotificationState);
    notify_if_ready(state, blocked,
        || register_0x19_bit0(),
        || { pmu_write_register_0x0c_one(); },
        || pmu_register_0x18_bit0(),
        || iram_usec_timer_read_veneer(),
        |slot, _timestamp| mailbox_slot_post(slot));
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn gates_write_and_notification_independently() {
        for blocked in [0, 1, u32::MAX] {
            for bit19 in [0, 1, u32::MAX] {
                for bit18 in [0, 1, u32::MAX] {
                    for tick in [0, 1, u32::MAX] {
                        let mut mailbox = core::ptr::null_mut();
                        let slot = &mut mailbox as *mut *mut Mailbox;
                        let mut state = NotificationState { flags: 0xdeadbeef, mailbox_slot: slot, timestamp: 42 };
                        let events = RefCell::new(std::vec::Vec::new());
                        notify_if_ready(&mut state, blocked,
                            || { events.borrow_mut().push("read19"); bit19 },
                            || { events.borrow_mut().push("write0c"); },
                            || { events.borrow_mut().push("read18"); bit18 },
                            || { events.borrow_mut().push("timer"); tick },
                            |posted_slot, saved_tick| {
                                assert_eq!(posted_slot, slot);
                                assert_eq!(saved_tick, tick);
                                events.borrow_mut().push("post");
                            });
                        let mut expected = std::vec::Vec::new();
                        if blocked == 0 {
                            expected.push("read19");
                            if bit19 != 0 { expected.push("write0c"); }
                            expected.push("read18");
                            if bit18 != 0 { expected.extend(["timer", "post"]); }
                        }
                        assert_eq!(*events.borrow(), expected);
                        assert_eq!(state.timestamp, if blocked == 0 && bit18 != 0 { tick } else { 42 });
                        assert_eq!(state.flags, 0xdeadbeef);
                        assert_eq!(state.mailbox_slot, slot);
                    }
                }
            }
        }
    }
}
