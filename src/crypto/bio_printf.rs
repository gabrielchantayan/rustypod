//! OpenSSL's `BIO_printf` — the variadic formatted-write front end of
//! the BIO (Basic I/O) abstraction Apple vendored with OpenSSL.
//!
//! Port: `bio_printf` — `FUN_0803d680` @ 0x0803d680 (28 bytes,
//! 0x0803d680..0x0803d69c; **25 call sites**, binary-verified by
//! decoding every B/BL word in osos.dec: all 25 are unconditional `bl`
//! — no predicated forms, no tail branches, so no caller NULL-guards or
//! flag-gates this entry point. No DATA word in the image holds the
//! address, so it is never dispatched virtually).
//!
//! # Decoded from the raw ARM at 0x0803d680
//!
//! ```text
//! push  {r0, r1, r2, r3}   ; home the argument registers
//! push  {r4, lr}
//! ldr   r1, [sp, #12]      ; the spilled r1 — the format string
//! add   r2, sp, #16        ; &spilled r2 — the va_list
//! bl    0x0803d970         ; BIO_vprintf(bio, format, ap)
//! pop   {r4}
//! ldr   pc, [sp], #20      ; lr -> pc, dropping lr + the 4 spill words
//! ```
//!
//! Seven instructions, no literal pool; 0x0803d69c starts the next
//! function (BIO_push, its own `push`) — Ghidra's 28-byte extent is
//! right. The textbook AAPCS variadic prologue: spill r0-r3 into a
//! frame contiguous with the caller's stacked arguments, reload the
//! fixed parameters, and call the `v`-flavored worker with a pointer
//! just past them. In C, upstream crypto/bio/b_print.c:
//! `int BIO_printf(BIO *bio, const char *format, ...) { va_start;
//! return BIO_vprintf(bio, format, args); }`.
//!
//! # Why this is OpenSSL's BIO layer
//!
//! The callee cluster 0x0803d294-0x0803da74 is `bio_lib.c` /
//! `b_print.c`, binary-verified:
//!
//! - The worker @ 0x0803d970 is `BIO_vprintf`: it formats through the
//!   `_dopr`-style engine @ 0x080e7a68 into a 2048-byte stack buffer
//!   (growing into an allocation freed through traced_free @
//!   0x08043994 when the text does not fit), passing the literal
//!   `"doapr()"` @ 0x0803da1c — OpenSSL b_print.c's function-name
//!   string — then emits with `BIO_write`.
//! - `BIO_write` @ 0x0803da74 invokes the BIO callback @ bio+0x04
//!   with code **3** (`BIO_CB_WRITE`), calls the method's `bwrite`
//!   (vtable +0x08), and on success adds the count to the byte counter
//!   @ bio+0x34 (`num_write`).
//! - `BIO_ctrl` @ 0x0803d294 dispatches cmd through the callback with
//!   code **6** (`BIO_CB_CTRL`); `BIO_push` @ 0x0803d69c walks the
//!   `next_bio` chain @ bio+0x24, links `prev_bio` @ bio+0x28, and
//!   notifies with `BIO_ctrl(b, 6, 0, 0)` — `BIO_CTRL_PUSH`.
//! - Failure paths log through the diagnostic ring (diag_ring_record
//!   @ 0x08049a84, kernel/diag_ring_record.rs) with facility **32** —
//!   `ERR_LIB_BIO` — and subsystem codes 113/120/121, the bio_lib.c
//!   line numbers of the failing checks.
//! - Callers are the X.509v3 display code: 0x08051098 prints
//!   GeneralName strings ("email: %s", "DNS: %s", "URI: %s",
//!   "DirName: ") and 0x08039cac formats certificate times
//!   ("%s %2d %02d:%02d:%02d %d%s"), returning 0 when `BIO_printf`'s
//!   result is < 1 — the caller treats the write's success as its own.
//!
//! # Deviations
//!
//! - The `...` becomes an explicit `args: VaList` (`*const u32`), the
//!   house convention (printf/printf_api.rs, stdio/debug_printf.rs).
//!   That IS what the original builds: the spill frame exists only to
//!   manufacture the pointer this signature takes directly. A variadic
//!   C caller needs the capture trampoline printf_api.rs documents.
//! - `BIO_vprintf` @ 0x0803d970 is not ported yet, so it rides the
//!   [`BIO_VPRINTF`] slot: on target the default calls 0x0803d970 in
//!   place; on host it panics until a test installs one.

use crate::printf::printf_api::VaList;
use core::ffi::c_void;

/// The worker's signature: BIO, format string, and a pointer to the
/// first variadic argument word. Returns the `BIO_write` result (the
/// byte count, or <= 0 on failure).
pub type BioVprintfFn =
    unsafe extern "C" fn(bio: *mut c_void, format: *const u8, args: VaList) -> i32;

/// Target default: the stock `BIO_vprintf` @ 0x0803d970, called in
/// place until it is ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bio_vprintf(bio: *mut c_void, format: *const u8, args: VaList) -> i32 {
    let worker: BioVprintfFn = unsafe { core::mem::transmute(0x0803_d970usize) };
    unsafe { worker(bio, format, args) }
}

/// Host default: nothing to forward to, and silently returning 0 would
/// make a missing install look like a successful write.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_vprintf(_bio: *mut c_void, _format: *const u8, _args: VaList) -> i32 {
    panic!("bio_printf requires the BIO_vprintf worker 0x0803d970")
}

/// The active `BIO_vprintf` worker. Host tests install recording mocks.
#[cfg(target_os = "none")]
pub static mut BIO_VPRINTF: BioVprintfFn = firmware_bio_vprintf;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut BIO_VPRINTF: BioVprintfFn = missing_bio_vprintf;

/// Reads the worker slot. Volatile so a build in which nothing rewrites
/// the slot cannot constant-fold the default in and delete the dispatch
/// (house rule, see stdio/semihost.rs).
#[inline(always)]
unsafe fn bio_vprintf() -> BioVprintfFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BIO_VPRINTF)) }
}

/// bio_printf — original: `FUN_0803d680` @ 0x0803d680 (28 bytes; 25
/// call sites, all unconditional `bl` — binary-verified).
///
/// The varargs front end of OpenSSL's formatted BIO write: hands the
/// BIO, the format string, and the argument list to `BIO_vprintf` @
/// 0x0803d970 and returns its result unchanged (the underlying
/// `BIO_write` byte count, or <= 0 on failure — callers such as the
/// X.509v3 display code test `< 1`). Nothing is validated: a NULL BIO
/// or NULL format reaches the worker exactly as in the original, whose
/// callers never gate the call (all 25 sites are unconditional).
///
/// # Safety
///
/// `bio` must name a live BIO and `format`/`args` must satisfy the
/// worker: a NUL-terminated format and enough argument words for its
/// conversions. [`BIO_VPRINTF`] must be installed on host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_printf(bio: *mut c_void, format: *const u8, args: VaList) -> i32 {
    unsafe { (bio_vprintf())(bio, format, args) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes swaps of [`BIO_VPRINTF`].
    static WORKER_LOCK: Mutex<()> = Mutex::new(());

    /// What the recording worker saw, in order.
    static mut SEEN: Vec<(*mut c_void, *const u8, VaList)> = Vec::new();
    /// Results the recorder returns, one per call, then repeating the last.
    static mut RESULTS: Vec<i32> = Vec::new();

    unsafe extern "C" fn recording_vprintf(bio: *mut c_void, format: *const u8, args: VaList) -> i32 {
        unsafe {
            let seen = &mut *core::ptr::addr_of_mut!(SEEN);
            seen.push((bio, format, args));
            let results = &*core::ptr::addr_of!(RESULTS);
            results[(seen.len() - 1).min(results.len() - 1)]
        }
    }

    /// Restores the shipped default even when a test panics.
    struct WorkerGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BIO_VPRINTF).write(missing_bio_vprintf);
                (*core::ptr::addr_of_mut!(SEEN)).clear();
            }
        }
    }

    fn install(results: &[i32]) -> WorkerGuard {
        let guard = WORKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(SEEN)).clear();
            let slot = &mut *core::ptr::addr_of_mut!(RESULTS);
            slot.clear();
            slot.extend_from_slice(results);
            core::ptr::addr_of_mut!(BIO_VPRINTF).write(recording_vprintf);
        }
        WorkerGuard(guard)
    }

    fn seen() -> Vec<(*mut c_void, *const u8, VaList)> {
        unsafe { (*core::ptr::addr_of!(SEEN)).clone() }
    }

    #[test]
    fn hands_the_bio_format_and_argument_list_to_the_worker_untouched() {
        let _guard = install(&[12]);
        // The stock frame is the spilled r2..r3 followed by the caller's
        // stacked arguments, i.e. one contiguous run of words.
        let arg_words: [u32; 3] = [0x0808_9038, 7, 0xffff_ffff];
        let fmt = b"_scrlNum_ %d\0";
        let mut bio = [0u32; 16]; // stand-in BIO; the veneer never dereferences it

        let rc = unsafe { bio_printf(bio.as_mut_ptr() as *mut c_void, fmt.as_ptr(), arg_words.as_ptr()) };

        assert_eq!(rc, 12, "the worker's write count is returned unchanged");
        assert_eq!(
            seen(),
            std::vec![(
                bio.as_mut_ptr() as *mut c_void,
                fmt.as_ptr() as *const u8,
                arg_words.as_ptr() as VaList
            )],
            "BIO, format, and va_list arrive as passed — no copy, no validation"
        );
    }

    #[test]
    fn propagates_a_failing_write_result_rather_than_forcing_success() {
        // BIO_write reports <= 0 on failure and callers test `< 1`
        // (the X.509v3 time formatter bails out on it); this entry
        // point does not synthesize that: it returns whatever the
        // worker left in r0.
        let _guard = install(&[-1]);
        let fmt = b"\0";

        let rc = unsafe { bio_printf(core::ptr::null_mut(), fmt.as_ptr(), core::ptr::null()) };

        assert_eq!(rc, -1);
    }

    #[test]
    fn passes_a_null_bio_and_format_straight_through() {
        // No guard exists in the original; all 25 call sites are
        // unconditional `bl` — callers never gate on the BIO pointer.
        let _guard = install(&[0]);

        let rc = unsafe { bio_printf(core::ptr::null_mut(), core::ptr::null(), core::ptr::null()) };

        assert_eq!(rc, 0);
        assert_eq!(seen().len(), 1, "the worker is entered even so");
        assert!(seen()[0].0.is_null());
        assert!(seen()[0].1.is_null());
    }

    #[test]
    fn re_reads_the_worker_slot_on_every_call() {
        let _guard = install(&[7, 9]);
        let fmt = b"email: %s\0";
        let first: [u32; 1] = [1];
        let second: [u32; 1] = [2];

        let a = unsafe { bio_printf(core::ptr::null_mut(), fmt.as_ptr(), first.as_ptr()) };
        let b = unsafe { bio_printf(core::ptr::null_mut(), fmt.as_ptr(), second.as_ptr()) };

        assert_eq!((a, b), (7, 9), "nothing is cached between calls");
        assert_eq!(
            seen(),
            std::vec![
                (core::ptr::null_mut(), fmt.as_ptr() as *const u8, first.as_ptr() as VaList),
                (core::ptr::null_mut(), fmt.as_ptr() as *const u8, second.as_ptr() as VaList),
            ],
            "each call carries its own argument frame"
        );
    }
}
