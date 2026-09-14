//! `status_gate_is_ready` — original: `FUN_0810799c` @ 0x0810799c
//! (44 bytes; exactly 6 direct `bl` call sites, all unconditional, and no
//! predicated call forms — verified by decoding every ARM B/BL word in
//! `osos.dec`).
//!
//! Reads bit 19 of the status-gate register at 0x3840_0000. When that bit is
//! clear it returns zero without calling anything. When set, it calls the
//! firmware routine at 0x0836e164 and normalizes that routine's nonzero result
//! to one.
//!
//! # Deviation
//!
//! The callee at 0x0836e164 has no `ported` ledger entry. Target builds reach
//! it at its verified firmware address without assigning it an identity; host
//! builds expose a test-only replacement seam.

/// Status-gate register used by the retail driver.
const STATUS_GATE_REGISTER: usize = 0x3840_0000;
const STATUS_GATE_BIT: u32 = 0x0008_0000;

#[cfg(target_os = "none")]
const STATUS_COMPLETION_DISPATCH_ADDR: usize = 0x0836_e164;

type StatusCompletionDispatch = unsafe extern "C" fn() -> u32;

#[cfg(not(target_os = "none"))]
static mut STATUS_COMPLETION_DISPATCH: Option<StatusCompletionDispatch> = None;

#[cfg(not(target_os = "none"))]
static mut HOST_STATUS_GATE_WORD: u32 = 0;

/// Evaluates the hardware gate and completion result using retail truthiness.
#[inline]
pub const fn status_gate_ready(status_gate_word: u32, completion_status: u32) -> u32 {
    if status_gate_word & STATUS_GATE_BIT != 0 && completion_status != 0 {
        1
    } else {
        0
    }
}

/// Calls the unported completion-status routine at 0x0836e164.
#[inline(always)]
unsafe fn status_completion_dispatch() -> u32 {
    #[cfg(target_os = "none")]
    {
        let dispatch: StatusCompletionDispatch = core::mem::transmute(STATUS_COMPLETION_DISPATCH_ADDR);
        dispatch()
    }
    #[cfg(not(target_os = "none"))]
    {
        match core::ptr::read_volatile(core::ptr::addr_of!(STATUS_COMPLETION_DISPATCH)) {
            Some(dispatch) => dispatch(),
            None => panic!("status_gate_is_ready requires dispatcher 0x0836e164"),
        }
    }
}

#[inline(always)]
unsafe fn status_gate_word() -> u32 {
    #[cfg(target_os = "none")]
    {
        (STATUS_GATE_REGISTER as *const u32).read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_STATUS_GATE_WORD))
    }
}

/// Returns whether the hardware status gate and completion status are both set.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn status_gate_is_ready() -> u32 {
    let gate_word = status_gate_word();
    if gate_word & STATUS_GATE_BIT == 0 {
        return 0;
    }
    status_gate_ready(gate_word, status_completion_dispatch())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: usize = 0;
    static mut DISPATCH_RESULT: u32 = 0;

    unsafe extern "C" fn record_dispatch() -> u32 {
        let calls = addr_of_mut!(DISPATCH_CALLS);
        calls.write_volatile(calls.read_volatile() + 1);
        addr_of!(DISPATCH_RESULT).read_volatile()
    }

    #[test]
    fn gate_clear_skips_completion_dispatch() {
        let _dispatch_guard = DISPATCH_LOCK.lock();
        unsafe {
            addr_of_mut!(STATUS_COMPLETION_DISPATCH).write_volatile(Some(record_dispatch));
            addr_of_mut!(HOST_STATUS_GATE_WORD).write_volatile(STATUS_GATE_BIT - 1);
            addr_of_mut!(DISPATCH_CALLS).write_volatile(0);

            assert_eq!(status_gate_is_ready(), 0);
            assert_eq!(addr_of!(DISPATCH_CALLS).read_volatile(), 0);

            addr_of_mut!(STATUS_COMPLETION_DISPATCH).write_volatile(None);
        }
    }

    #[test]
    fn gate_set_normalizes_all_completion_truthy_values() {
        let _dispatch_guard = DISPATCH_LOCK.lock();
        unsafe {
            addr_of_mut!(STATUS_COMPLETION_DISPATCH).write_volatile(Some(record_dispatch));
            addr_of_mut!(HOST_STATUS_GATE_WORD).write_volatile(STATUS_GATE_BIT | 0xffff_ffff);
            addr_of_mut!(DISPATCH_CALLS).write_volatile(0);

            for (completion_status, expected) in [(0, 0), (1, 1), (0x8000_0000, 1), (u32::MAX, 1)] {
                addr_of_mut!(DISPATCH_RESULT).write_volatile(completion_status);
                assert_eq!(status_gate_is_ready(), expected, "completion_status={completion_status:#x}");
            }
            assert_eq!(addr_of!(DISPATCH_CALLS).read_volatile(), 4);

            addr_of_mut!(STATUS_COMPLETION_DISPATCH).write_volatile(None);
        }
    }

    #[test]
    fn pure_model_requires_both_conditions() {
        for status_gate_word in [0, STATUS_GATE_BIT - 1, STATUS_GATE_BIT, u32::MAX] {
            for completion_status in [0, 1, u32::MAX] {
                assert_eq!(
                    status_gate_ready(status_gate_word, completion_status),
                    u32::from(status_gate_word & STATUS_GATE_BIT != 0 && completion_status != 0),
                );
            }
        }
    }
}
