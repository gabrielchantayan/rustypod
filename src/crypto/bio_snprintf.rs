//! OpenSSL's `BIO_snprintf` — bounded formatting into a caller buffer.
//!
//! Port: `bio_snprintf` — `FUN_0803d954` @ 0x0803d954 (28 bytes,
//! 0x0803d954..0x0803d970; **16 direct `bl` call sites**, binary-verified
//! by decoding every ARM B/BL word in osos.dec: 14 unconditional `bl` and
//! two `bleq` (0x08049750 and 0x08049768), with no tail branches. The two
//! predicated calls create fallback text only when their preceding helper
//! result is NULL; the veneer itself has no NULL guard. No image DATA word
//! holds 0x0803d954, so it is not a virtual dispatch target.
//!
//! # Decoded from the raw ARM at 0x0803d954
//!
//! ```text
//! push {r0, r1, r2, r3}       ; home the argument registers
//! push {r4, lr}
//! ldr  r2, [sp, #16]          ; spilled r2, the format string
//! add  r3, sp, #20            ; spilled r3, the va_list
//! bl   0x0803da24             ; BIO_vsnprintf(buf, size, format, ap)
//! pop  {r4}
//! ldr  pc, [sp], #20          ; preserve r0 and discard the spill frame
//! ```
//!
//! Seven instructions, no literal pool; `BIO_vprintf` starts at 0x0803d970,
//! proving Ghidra's 28-byte extent. This is the standard OpenSSL b_print.c
//! variadic wrapper: it passes the caller buffer, byte count, format, and
//! a va_list formed from the spilled third argument to `BIO_vsnprintf`.
//!
//! # Deliberate deviation
//!
//! Stable Rust has no C-variadic definition, so `args` explicitly supplies
//! the `VaList` (`*const u32`) which the stock spill frame creates. The
//! unported `BIO_vsnprintf` worker @ 0x0803da24 remains a volatile dispatch
//! seam: target builds call that firmware address; host builds require an
//! installed test worker rather than reporting a fabricated formatting result.

use crate::printf::printf_api::VaList;

/// `BIO_vsnprintf(buf, size, format, args)` @ 0x0803da24.
pub type BioVsnprintfFn = unsafe extern "C" fn(
    buf: *mut u8,
    size: usize,
    format: *const u8,
    args: VaList,
) -> i32;

/// Target default: invoke the retailOS worker in place until it is ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bio_vsnprintf(
    buf: *mut u8,
    size: usize,
    format: *const u8,
    args: VaList,
) -> i32 {
    let worker: BioVsnprintfFn = unsafe { core::mem::transmute(0x0803_da24usize) };
    unsafe { worker(buf, size, format, args) }
}

/// Host default: formatting must not look successful without a worker.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_vsnprintf(
    _buf: *mut u8,
    _size: usize,
    _format: *const u8,
    _args: VaList,
) -> i32 {
    panic!("bio_snprintf requires the BIO_vsnprintf worker 0x0803da24")
}

/// Active `BIO_vsnprintf` worker. Host tests replace this volatile seam.
#[cfg(target_os = "none")]
pub static mut BIO_VSNPRINTF: BioVsnprintfFn = firmware_bio_vsnprintf;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut BIO_VSNPRINTF: BioVsnprintfFn = missing_bio_vsnprintf;

#[inline(always)]
unsafe fn bio_vsnprintf() -> BioVsnprintfFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BIO_VSNPRINTF)) }
}

/// bio_snprintf — original: `FUN_0803d954` @ 0x0803d954 (28 bytes; 16
/// direct `bl` call sites: 14 unconditional, 2 `bleq`, binary-verified).
///
/// Formats the variadic words at `args` into `buf` through `BIO_vsnprintf` @
/// 0x0803da24, returning that worker's result unchanged. It neither validates
/// nor accesses `buf`, `format`, or `args`; a NULL pointer and `size == 0`
/// therefore reach the worker exactly as in the raw ARM veneer.
///
/// # Safety
///
/// `buf`, `format`, and `args` must meet the worker's requirements. On host,
/// [`BIO_VSNPRINTF`] must first be installed with a suitable worker.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_snprintf(
    buf: *mut u8,
    size: usize,
    format: *const u8,
    args: VaList,
) -> i32 {
    unsafe { (bio_vsnprintf())(buf, size, format, args) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static WORKER_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN: Vec<(*mut u8, usize, *const u8, VaList)> = Vec::new();
    static mut RESULTS: Vec<i32> = Vec::new();

    unsafe extern "C" fn recording_vsnprintf(
        buf: *mut u8,
        size: usize,
        format: *const u8,
        args: VaList,
    ) -> i32 {
        unsafe {
            let seen = &mut *core::ptr::addr_of_mut!(SEEN);
            seen.push((buf, size, format, args));
            let results = &*core::ptr::addr_of!(RESULTS);
            results[(seen.len() - 1).min(results.len() - 1)]
        }
    }

    struct WorkerGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BIO_VSNPRINTF).write(missing_bio_vsnprintf);
                (*core::ptr::addr_of_mut!(SEEN)).clear();
            }
        }
    }

    fn install(results: &[i32]) -> WorkerGuard {
        let guard = WORKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(SEEN)).clear();
            let result_log = &mut *core::ptr::addr_of_mut!(RESULTS);
            result_log.clear();
            result_log.extend_from_slice(results);
            core::ptr::addr_of_mut!(BIO_VSNPRINTF).write(recording_vsnprintf);
        }
        WorkerGuard(guard)
    }

    fn seen() -> Vec<(*mut u8, usize, *const u8, VaList)> {
        unsafe { (*core::ptr::addr_of!(SEEN)).clone() }
    }

    #[test]
    fn forwards_all_arguments_and_the_worker_count_unchanged() {
        let _guard = install(&[17]);
        let mut buf = [0xaau8; 8];
        let format = b"serial=%08lX\0";
        let args: [u32; 2] = [0x1234_5678, 0x9abc_def0];

        let rc = unsafe { bio_snprintf(buf.as_mut_ptr(), buf.len(), format.as_ptr(), args.as_ptr()) };

        assert_eq!(rc, 17);
        assert_eq!(
            seen(),
            std::vec![(buf.as_mut_ptr(), buf.len(), format.as_ptr(), args.as_ptr())],
            "the veneer only builds a va_list; it does not copy or inspect any input"
        );
        assert_eq!(buf, [0xaa; 8], "only the worker may write the output buffer");
    }

    #[test]
    fn forwards_nulls_and_zero_size_without_a_guard() {
        let _guard = install(&[-1]);

        let rc = unsafe { bio_snprintf(core::ptr::null_mut(), 0, core::ptr::null(), core::ptr::null()) };

        assert_eq!(rc, -1, "the formatter failure remains visible to callers");
        assert_eq!(seen(), std::vec![(core::ptr::null_mut(), 0, core::ptr::null(), core::ptr::null())]);
    }

    #[test]
    fn reloads_the_worker_slot_for_each_call() {
        let _guard = install(&[3, 5]);
        let first: [u32; 1] = [1];
        let second: [u32; 1] = [2];

        let a = unsafe { bio_snprintf(core::ptr::null_mut(), 1, b"a\0".as_ptr(), first.as_ptr()) };
        let b = unsafe { bio_snprintf(core::ptr::null_mut(), 2, b"b\0".as_ptr(), second.as_ptr()) };

        assert_eq!((a, b), (3, 5));
        assert_eq!(
            seen(),
            std::vec![
                (core::ptr::null_mut(), 1, b"a\0".as_ptr(), first.as_ptr()),
                (core::ptr::null_mut(), 2, b"b\0".as_ptr(), second.as_ptr()),
            ]
        );
    }
}
