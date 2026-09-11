//! `debug_pager_read_key` — original: `FUN_082d997c` @ 0x082d997c (72 code
//! bytes plus a 12-byte trailing literal pool).
//!
//! Raw ARM body (`0x082d997c..0x082d99c0`) loads the gate word at
//! `0x089ca3c4`; a nonzero value returns zero without any semihosting call.
//! Otherwise it issues Angel `SYS_WRITE0` (op 4) with the literal
//! `0x083e2484`, issues `SYS_READC` (op 7) with a null `r1`, saves that result,
//! then issues a second `SYS_WRITE0` with `0x083e2480` and returns the saved
//! character. `0x082d99c4..0x082d99cc` is the three-word literal pool; the
//! separately linked next function starts at `0x082d99d0`.
//!
//! The eight direct callers are all plain unconditional `bl` instructions:
//! `0x082beef0`, `0x082bf2fc`, `0x082bf454`, `0x082bf924`, `0x082bfcc4`,
//! `0x082bffb8`, `0x082c00b8`, and `0x082c0310`. They page diagnostic table
//! dumps and treat `X`/`x` as stop input, establishing this as the diagnostic
//! pager's key reader.
//!
//! Deliberate deviation: on target the gate remains a volatile read from its
//! retailOS address. Host builds model that word with a private static so the
//! branch is testable. The two SYS_WRITE0 pointer literals decode to live code
//! at `0x083e2480`, not established C strings; their meaning is not invented,
//! and this port forwards the exact values.

use super::semihost::{semihost_swi, SYS_READC, SYS_WRITE0};

/// The retailOS word whose nonzero state suppresses pager I/O.
const DEBUG_PAGER_GATE_ADDR: usize = 0x089c_a3c4;
/// First raw SYS_WRITE0 argument from the literal pool at 0x082d99c8.
const DEBUG_PAGER_WRITE_BEFORE_READ: usize = 0x083e_2484;
/// Second raw SYS_WRITE0 argument from the literal pool at 0x082d99cc.
const DEBUG_PAGER_WRITE_AFTER_READ: usize = 0x083e_2480;

#[cfg(not(target_os = "none"))]
static mut DEBUG_PAGER_GATE_HOST: u32 = 0;

#[inline(always)]
unsafe fn pager_io_suppressed() -> bool {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::read_volatile(DEBUG_PAGER_GATE_ADDR as *const u32) != 0 }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEBUG_PAGER_GATE_HOST)) != 0 }
    }
}

/// `debug_pager_read_key` — original: `FUN_082d997c` @ 0x082d997c (72 bytes,
/// followed by its 12-byte literal pool).
///
/// Returns zero without I/O when the pager gate word is nonzero. Otherwise it
/// forwards the original three semihost operations, returns only the SYS_READC
/// result, and discards both SYS_WRITE0 results.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn debug_pager_read_key() -> i32 {
    if unsafe { pager_io_suppressed() } {
        return 0;
    }

    unsafe {
        semihost_swi()(SYS_WRITE0, DEBUG_PAGER_WRITE_BEFORE_READ as *const usize);
        let key = semihost_swi()(SYS_READC, core::ptr::null());
        semihost_swi()(SYS_WRITE0, DEBUG_PAGER_WRITE_AFTER_READ as *const usize);
        key
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::stdio::semihost::{tests::SWI_LOCK, SemihostSwiFn, SEMIHOST_SWI};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static mut CALLS: Vec<(usize, usize)> = Vec::new();
    static mut READ_RESULT: i32 = 0;

    unsafe extern "C" fn record_swi(op: usize, block: *const usize) -> i32 {
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).push((op, block as usize));
            if op == SYS_READC { READ_RESULT } else { -1 }
        }
    }

    struct PagerGuard {
        _swi_lock: MutexGuard<'static, ()>,
        old_swi: SemihostSwiFn,
        old_gate: u32,
    }

    impl Drop for PagerGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SEMIHOST_SWI).write(self.old_swi);
                core::ptr::addr_of_mut!(DEBUG_PAGER_GATE_HOST).write(self.old_gate);
                (*core::ptr::addr_of_mut!(CALLS)).clear();
            }
        }
    }

    fn install(gate: u32, read_result: i32) -> PagerGuard {
        let swi_lock = SWI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let old_swi = core::ptr::read_volatile(core::ptr::addr_of!(SEMIHOST_SWI));
            let old_gate = core::ptr::read_volatile(core::ptr::addr_of!(DEBUG_PAGER_GATE_HOST));
            core::ptr::addr_of_mut!(SEMIHOST_SWI).write(record_swi);
            core::ptr::addr_of_mut!(DEBUG_PAGER_GATE_HOST).write(gate);
            core::ptr::addr_of_mut!(READ_RESULT).write(read_result);
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            PagerGuard { _swi_lock: swi_lock, old_swi, old_gate }
        }
    }

    #[test]
    fn nonzero_gate_returns_zero_without_semihosting() {
        let _guard = install(1, b'X' as i32);
        assert_eq!(unsafe { debug_pager_read_key() }, 0);
        assert!(unsafe { (*core::ptr::addr_of!(CALLS)).is_empty() });
    }

    #[test]
    fn forwards_raw_pointers_and_returns_only_read_character() {
        let _guard = install(0, b'x' as i32);
        assert_eq!(unsafe { debug_pager_read_key() }, b'x' as i32);
        assert_eq!(
            unsafe { &*core::ptr::addr_of!(CALLS) },
            &[
                (SYS_WRITE0, DEBUG_PAGER_WRITE_BEFORE_READ),
                (SYS_READC, 0),
                (SYS_WRITE0, DEBUG_PAGER_WRITE_AFTER_READ),
            ],
        );
    }
}
