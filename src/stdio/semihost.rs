//! The ARM ADS 1.0.1 semihosting (Angel) SWI syscall wrappers from osos.
//!
//! Every wrapper marshals its arguments into a parameter block on the
//! stack, loads the operation code into r0 and the block address into r1,
//! and issues `swi 0x123456`. On the iPod there is no debugger attached to
//! trap the SWI, so this whole family is dead code on device — but the
//! buffered-stdio cluster (`stream_file.rs`) is built on top of it, so the
//! wrappers are ported faithfully.
//!
//! Ports (all `swi 0x123456` with the op in r0, block pointer in r1):
//! - `_sys_open`   @ 0x08031f84 (32 bytes) — op 0x01, block `[name, mode,
//!   strlen(name)]`. The original measures the name with the retailOS
//!   unguarded strlen @ 0x08392478; inlined here as [`strlen_raw`].
//! - `_sys_close`  @ 0x08031fa4 (24 bytes) — op 0x02, block `[handle]`.
//! - `_sys_write`  @ 0x08031fbc (32 bytes) — op 0x05, block `[handle, buf,
//!   len]`. Returns the number of bytes NOT written (0 = success).
//! - `_sys_read`   @ 0x08031fdc (32 bytes) — op 0x06, block `[handle, buf,
//!   len, mode]`. Returns the number of bytes NOT read; the caller
//!   (`stream_raw_read` @ 0x08034f88) passes the stream's flag word as
//!   `mode` and decodes EOF from bit 31 of the result.
//! - `_sys_istty`  @ 0x08031ffc (24 bytes) — op 0x09, block `[handle]`.
//! - `_sys_seek`   @ 0x08032014 (24 bytes) — op 0x0a, block `[handle, pos]`.
//! - `_sys_flen`   @ 0x08032034 (24 bytes) — op 0x0c, block `[handle]`.
//! - `_sys_writec` @ 0x08036d48 (24 bytes) — op 0x03, r1 points at the
//!   character (the argument word is parked on the stack and its address
//!   passed, so the little-endian first byte is the character).
//! - `sys_stub_ret0`   @ 0x0803202c (8 bytes) — `mov r0, #0; ret` (weak
//!   semihost stub of the tmpnam/ensure family).
//! - `sys_stub_ret0_2` @ 0x080320a0 (8 bytes) — identical second stub.
//! - `nop_stub`        @ 0x08036d08 (4 bytes) — `mov pc, lr` (weak hook
//!   target reached via 0x080358a0 from the abort report path).
//!
//! Deviations:
//! - The SWI boundary is the [`SEMIHOST_SWI`] dispatch hook instead of an
//!   inlined `swi` per wrapper: host tests mock it, and the firmware build
//!   defaults to [`semihost_swi_device`], which issues the original
//!   `swi 0x123456` encoding (ARM mode, immediate 0x123456).
//! - Parameter blocks are native-word (`usize`) arrays so pointer-bearing
//!   blocks stay well-formed on 64-bit test hosts; on the 32-bit target
//!   they are the original 32-bit word blocks.
//! - The blocks live in locals rather than at the original's exact
//!   stack-slot offsets (ABI-invisible).

/// Semihosting operation codes used by osos (Angel reason codes).
pub const SYS_OPEN: usize = 0x01;
/// See [`SYS_OPEN`].
pub const SYS_CLOSE: usize = 0x02;
/// See [`SYS_OPEN`].
pub const SYS_WRITEC: usize = 0x03;
/// See [`SYS_OPEN`].
pub const SYS_WRITE: usize = 0x05;
/// See [`SYS_OPEN`].
pub const SYS_READ: usize = 0x06;
/// See [`SYS_OPEN`].
pub const SYS_ISTTY: usize = 0x09;
/// See [`SYS_OPEN`].
pub const SYS_SEEK: usize = 0x0a;
/// See [`SYS_OPEN`].
pub const SYS_FLEN: usize = 0x0c;

/// The SWI boundary: op in r0, parameter-block address in r1, result in r0.
pub type SemihostSwiFn = unsafe extern "C" fn(op: usize, block: *const usize) -> i32;

/// Firmware-target SWI: the original `swi 0x123456` (Angel semihosting)
/// encoding. Dead on device — no debugger traps it — but bit-faithful.
#[cfg(all(target_os = "none", target_arch = "arm"))]
unsafe extern "C" fn semihost_swi_default(op: usize, block: *const usize) -> i32 {
    let ret;
    core::arch::asm!(
        "swi 0x123456",
        inlateout("r0") op => ret,
        in("r1") block,
        options(nostack),
    );
    ret
}

/// Host stand-in for the SWI: reports failure (-1) until a test installs
/// a mock through [`SEMIHOST_SWI`].
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
unsafe extern "C" fn semihost_swi_default(_op: usize, _block: *const usize) -> i32 {
    -1
}

/// The active SWI implementation: the real `swi 0x123456` on the firmware
/// target, a fail stub on hosts (tests install mocks here).
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut SEMIHOST_SWI: SemihostSwiFn = semihost_swi_default;

/// Reads the SWI dispatch slot. Volatile so a build in which nothing
/// rewrites the slot does not constant-fold the default in and delete the
/// dispatch (the slot is meant to be swapped at runtime).
#[inline(always)]
fn semihost_swi() -> SemihostSwiFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SEMIHOST_SWI)) }
}

/// Unguarded C string length — the retailOS strlen @ 0x08392478 that
/// `_sys_open` measures the filename with, inlined (it is a plain byte
/// loop; volatile reads keep LLVM from re-recognizing it as `strlen`).
unsafe fn strlen_raw(mut s: *const u8) -> usize {
    let mut len = 0;
    while core::ptr::read_volatile(s) != 0 {
        len += 1;
        s = s.add(1);
    }
    len
}

/// _sys_open — original @ 0x08031f84 (32 bytes).
///
/// Semihost SYS_OPEN: block `[name, mode, strlen(name)]`. Returns the file
/// handle, or -1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _sys_open(name: *const u8, mode: i32) -> i32 {
    let block = [name as usize, mode as usize, strlen_raw(name)];
    semihost_swi()(SYS_OPEN, block.as_ptr())
}

/// _sys_close — original @ 0x08031fa4 (24 bytes).
///
/// Semihost SYS_CLOSE: block `[handle]`. Returns 0 on success.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _sys_close(handle: i32) -> i32 {
    let block = [handle as usize];
    semihost_swi()(SYS_CLOSE, block.as_ptr())
}

/// _sys_write — original @ 0x08031fbc (32 bytes).
///
/// Semihost SYS_WRITE: block `[handle, buf, len]`. Returns the number of
/// bytes NOT written (0 = complete success).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _sys_write(handle: i32, buf: *const u8, len: u32) -> i32 {
    let block = [handle as usize, buf as usize, len as usize];
    semihost_swi()(SYS_WRITE, block.as_ptr())
}

/// _sys_read — original @ 0x08031fdc (32 bytes).
///
/// Semihost SYS_READ: block `[handle, buf, len, mode]`. Returns the number
/// of bytes NOT read; the stdio refill decodes EOF from bit 31.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _sys_read(handle: i32, buf: *mut u8, len: u32, mode: u32) -> i32 {
    let block = [handle as usize, buf as usize, len as usize, mode as usize];
    semihost_swi()(SYS_READ, block.as_ptr())
}

/// _sys_istty — original @ 0x08031ffc (24 bytes).
///
/// Semihost SYS_ISTTY: block `[handle]`. Nonzero = interactive device.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _sys_istty(handle: i32) -> i32 {
    let block = [handle as usize];
    semihost_swi()(SYS_ISTTY, block.as_ptr())
}

/// _sys_seek — original @ 0x08032014 (24 bytes).
///
/// Semihost SYS_SEEK: block `[handle, pos]` (absolute byte position).
/// Negative result = failure.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _sys_seek(handle: i32, pos: i32) -> i32 {
    let block = [handle as usize, pos as usize];
    semihost_swi()(SYS_SEEK, block.as_ptr())
}

/// _sys_flen — original @ 0x08032034 (24 bytes).
///
/// Semihost SYS_FLEN: block `[handle]`. Returns the file length, or -1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _sys_flen(handle: i32) -> i32 {
    let block = [handle as usize];
    semihost_swi()(SYS_FLEN, block.as_ptr())
}

/// _sys_writec — original @ 0x08036d48 (24 bytes).
///
/// Semihost SYS_WRITEC: the character is parked in a stack word and r1
/// points AT it (little-endian first byte), not at a block containing a
/// pointer. Result is whatever the SWI leaves in r0 (unspecified for
/// WRITEC; the wrapper returns it as the original does).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn _sys_writec(ch: i32) -> i32 {
    let block = [ch as usize];
    semihost_swi()(SYS_WRITEC, block.as_ptr())
}

/// sys_stub_ret0 — original @ 0x0803202c (8 bytes): `mov r0, #0; ret`.
/// Weak semihost stub (tmpnam/ensure family).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sys_stub_ret0() -> i32 {
    0
}

/// sys_stub_ret0_2 — original @ 0x080320a0 (8 bytes): the second
/// `mov r0, #0; ret` stub (several callers in the runtime region).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sys_stub_ret0_2() -> i32 {
    0
}

/// nop_stub — original @ 0x08036d08 (4 bytes): `mov pc, lr`. Weak hook
/// target (reached via 0x080358a0 from the abort report path).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn nop_stub() {}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap [`SEMIHOST_SWI`] (shared with the
    /// stream_file tests, which mock the same boundary).
    pub(crate) static SWI_LOCK: Mutex<()> = Mutex::new(());

    /// One recorded SWI: (op, up to four block words as issued).
    pub(crate) static mut SWI_LOG: Vec<(usize, Vec<usize>)> = Vec::new();
    /// Scripted results, consumed front to back; empty = -1.
    pub(crate) static mut SWI_RESULTS: Vec<i32> = Vec::new();

    /// Block word counts per op (how much of the block the mock records).
    fn block_len(op: usize) -> usize {
        match op {
            SYS_OPEN | SYS_WRITE => 3,
            SYS_READ => 4,
            SYS_SEEK => 2,
            _ => 1,
        }
    }

    /// Recording mock for the SWI boundary.
    pub(crate) unsafe extern "C" fn recording_swi(op: usize, block: *const usize) -> i32 {
        let words = (0..block_len(op)).map(|i| *block.add(i)).collect();
        (*core::ptr::addr_of_mut!(SWI_LOG)).push((op, words));
        let results = &mut *core::ptr::addr_of_mut!(SWI_RESULTS);
        if results.is_empty() {
            -1
        } else {
            results.remove(0)
        }
    }

    /// Locks the SWI boundary, installs the recording mock with the given
    /// scripted results, and clears the log.
    pub(crate) fn mock_swi(results: &[i32]) -> MutexGuard<'static, ()> {
        let guard = SWI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SEMIHOST_SWI = recording_swi;
            (*core::ptr::addr_of_mut!(SWI_LOG)).clear();
            *core::ptr::addr_of_mut!(SWI_RESULTS) = results.to_vec();
        }
        guard
    }

    /// Restores the default (fail-stub) SWI. Call before dropping the guard.
    pub(crate) fn restore_swi() {
        unsafe { SEMIHOST_SWI = semihost_swi_default };
    }

    fn log() -> Vec<(usize, Vec<usize>)> {
        unsafe { (*core::ptr::addr_of!(SWI_LOG)).clone() }
    }

    #[test]
    fn open_block_is_name_mode_strlen() {
        let _guard = mock_swi(&[7]);
        let name = b"log.txt\0";
        unsafe {
            assert_eq!(_sys_open(name.as_ptr(), 4), 7, "handle passed through");
        }
        let l = log();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].0, SYS_OPEN);
        assert_eq!(l[0].1, std::vec![name.as_ptr() as usize, 4, 7]);
        restore_swi();
    }

    #[test]
    fn open_measures_empty_name_as_zero() {
        let _guard = mock_swi(&[-1]);
        let name = b"\0";
        unsafe {
            assert_eq!(_sys_open(name.as_ptr(), 0), -1);
        }
        assert_eq!(log()[0].1[2], 0, "strlen of empty name");
        restore_swi();
    }

    #[test]
    fn close_istty_flen_single_word_blocks() {
        let _guard = mock_swi(&[0, 1, 0x1234]);
        unsafe {
            assert_eq!(_sys_close(5), 0);
            assert_eq!(_sys_istty(6), 1);
            assert_eq!(_sys_flen(7), 0x1234);
        }
        assert_eq!(
            log(),
            std::vec![
                (SYS_CLOSE, std::vec![5]),
                (SYS_ISTTY, std::vec![6]),
                (SYS_FLEN, std::vec![7]),
            ]
        );
        restore_swi();
    }

    #[test]
    fn write_block_and_not_written_result() {
        let _guard = mock_swi(&[3]);
        let buf = b"0123456789";
        unsafe {
            // 3 = three bytes were NOT written.
            assert_eq!(_sys_write(2, buf.as_ptr(), 10), 3);
        }
        assert_eq!(log(), std::vec![(SYS_WRITE, std::vec![2, buf.as_ptr() as usize, 10])]);
        restore_swi();
    }

    #[test]
    fn read_block_carries_the_mode_word() {
        let _guard = mock_swi(&[0]);
        let mut buf = [0u8; 8];
        unsafe {
            assert_eq!(_sys_read(3, buf.as_mut_ptr(), 8, 0xabcd), 0);
        }
        assert_eq!(
            log(),
            std::vec![(SYS_READ, std::vec![3, buf.as_mut_ptr() as usize, 8, 0xabcd])]
        );
        restore_swi();
    }

    #[test]
    fn seek_block_is_handle_pos() {
        let _guard = mock_swi(&[0]);
        unsafe {
            assert_eq!(_sys_seek(4, 0x400), 0);
        }
        assert_eq!(log(), std::vec![(SYS_SEEK, std::vec![4, 0x400])]);
        restore_swi();
    }

    #[test]
    fn writec_points_r1_at_the_character() {
        let _guard = mock_swi(&[0]);
        unsafe {
            assert_eq!(_sys_writec(b'Q' as i32), 0);
        }
        let l = log();
        assert_eq!(l[0].0, SYS_WRITEC);
        // The block's first word IS the character value: r1 points at the
        // word whose little-endian first byte is the character.
        assert_eq!(l[0].1, std::vec![b'Q' as usize]);
        restore_swi();
    }

    #[test]
    fn default_host_swi_fails() {
        let _guard = SWI_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_swi();
        unsafe {
            assert_eq!(_sys_close(1), -1);
            assert_eq!(_sys_flen(1), -1);
        }
    }

    #[test]
    fn stubs_return_zero_and_nop_returns() {
        unsafe {
            assert_eq!(sys_stub_ret0(), 0);
            assert_eq!(sys_stub_ret0_2(), 0);
            nop_stub();
        }
    }
}
