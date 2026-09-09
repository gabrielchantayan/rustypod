//! Counted wide-string equality under collation flags.
//!
//! - `counted_wstr_eq` — original: `FUN_08059b60` @ `0x08059b60`
//!   (40 bytes; 14 `bl` call sites, binary-scanned: every ARM B/BL word
//!   in `osos.dec` targeting `0x08059b60` — 14 unconditional `bl`,
//!   zero predicated forms, so no caller flag-gates this routine).
//!
//! Raw ARM decoded from `work/firmware/osos.dec`:
//!
//! ```text
//! push {r3, lr}
//! str  r2, [sp]           @ pass arg3 (flags) as the callee's 5th (stack) arg
//! ldrh ip, [r0], #2       @ ip = a[0] (count); r0 = a + 1
//! ldrh r3, [r1]           @ r3 = b[0] (count)
//! add  r2, r1, #2         @ r2 = b + 1
//! mov  r1, ip
//! bl   0x0804529c         @ counted_wstr_compare(a+1, a[0], b+1, b[0], flags)
//! rsbs r0, r0, #1
//! movcc r0, #0            @ r0 = 1 iff compare returned 0, else 0
//! pop  {ip, pc}
//! ```
//!
//! Both operands are counted UTF-16 strings: a `u16` element count
//! immediately followed by that many `u16` elements. The wrapper reads
//! both counts, passes the payloads and counts to the counted
//! wide-string compare at `0x0804529c` with the caller's option flags,
//! and returns strict equality of its tri-state result: 1 iff the
//! compare returned exactly 0, else 0 (`rsbs`/`movcc` maps 0 -> 1 and
//! every other value — including negative tri-states, which are huge
//! unsigned — to 0).
//!
//! The compare at `0x0804529c` (396 bytes, not ported) is a counted
//! UTF-16 tri-state compare with collation flags: bit 0 skips leading
//! elements `<= 0x20` on both sides and folds `a..z` to uppercase
//! before comparing, bit 2 routes straight to the generic collate
//! engine at `0x08045c24`, bit 3 is forwarded to that engine, bit 4
//! bails to the engine when both current elements are ASCII digits
//! (numeric run handling), and any element above `0x7a` or missing
//! from the 256-entry weight table also bails. All observed callers
//! pass flags = 0, i.e. plain case-sensitive equality.
//!
//! Deliberate deviation: `0x0804529c` has no `ported` ledger entry, so
//! its retail call is an explicit [`COUNTED_WSTR_COMPARE`] dispatch
//! seam (the `stdio/debug_printf.rs` precedent): target builds
//! transmute `0x0804529c`; host builds default to a placeholder and
//! tests substitute a recorder. The five-argument `extern "C"` ABI
//! places `flags` on the stack under AAPCS, exactly matching the
//! original's `str r2, [sp]`.

use core::ptr;

/// ABI of the still-unported counted wide-string compare at
/// `0x0804529c`: `(s1, len1, s2, len2, flags) -> -1 / 0 / 1`.
pub type CountedWstrCompareFn =
    unsafe extern "C" fn(*const u16, u32, *const u16, u32, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_counted_wstr_compare(
    s1: *const u16,
    len1: u32,
    s2: *const u16,
    len2: u32,
    flags: u32,
) -> i32 {
    let compare: CountedWstrCompareFn = core::mem::transmute(0x0804_529cusize);
    compare(s1, len1, s2, len2, flags)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_counted_wstr_compare(
    _s1: *const u16,
    _len1: u32,
    _s2: *const u16,
    _len2: u32,
    _flags: u32,
) -> i32 {
    // Host placeholder for the unported collate compare: reports
    // "not equal". Tests substitute a recorder through the seam.
    1
}

/// Active counted wide-string compare boundary.
///
/// `static mut`, swapped at test/bring-up time only — same discipline
/// as the firmware's own hook tables.
pub static mut COUNTED_WSTR_COMPARE: CountedWstrCompareFn = retail_counted_wstr_compare;

#[inline(always)]
fn counted_wstr_compare_fn() -> CountedWstrCompareFn {
    unsafe { ptr::read_volatile(ptr::addr_of!(COUNTED_WSTR_COMPARE)) }
}

/// counted_wstr_eq — original: `FUN_08059b60` @ `0x08059b60` (40 bytes).
///
/// 1 iff the counted UTF-16 strings at `a` and `b` (a `u16` element
/// count followed by that many elements) compare equal under `flags`,
/// else 0. The counts are unsigned 16-bit; the flags word is passed
/// through to the collate compare untouched.
///
/// # Safety
/// `a` and `b` must each be readable for one `u16` count; the payload
/// reads happen only inside the dispatched compare, which must be able
/// to read `count` elements past each header.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.counted_wstr_eq")]
#[inline(never)]
pub unsafe extern "C" fn counted_wstr_eq(a: *const u16, b: *const u16, flags: u32) -> u32 {
    let len_a = u32::from(a.read_volatile());
    let len_b = u32::from(b.read_volatile());
    let compare = counted_wstr_compare_fn();
    u32::from(compare(a.add(1), len_a, b.add(1), len_b, flags) == 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    static COMPARE_LOCK: Mutex<()> = Mutex::new(());

    struct Recorded {
        s1: *const u16,
        len1: u32,
        s2: *const u16,
        len2: u32,
        flags: u32,
    }

    static mut CALLS: Vec<Recorded> = Vec::new();
    static mut RESULT: i32 = 0;

    unsafe extern "C" fn record_compare(
        s1: *const u16,
        len1: u32,
        s2: *const u16,
        len2: u32,
        flags: u32,
    ) -> i32 {
        CALLS.push(Recorded {
            s1,
            len1,
            s2,
            len2,
            flags,
        });
        RESULT
    }

    struct SeamGuard(CountedWstrCompareFn);

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe { COUNTED_WSTR_COMPARE = self.0 };
        }
    }

    unsafe fn install_recorder(result: i32) -> SeamGuard {
        let previous = COUNTED_WSTR_COMPARE;
        COUNTED_WSTR_COMPARE = record_compare;
        CALLS.clear();
        RESULT = result;
        SeamGuard(previous)
    }

    /// The counts come from the `u16` headers, the payloads start one
    /// element past them, and `flags` passes through untouched.
    #[test]
    fn marshals_counts_payloads_and_flags() {
        let _lock = COMPARE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let a: [u16; 4] = [3, 0x61, 0x62, 0x63];
        let b: [u16; 4] = [3, 0x61, 0x62, 0x63];
        unsafe {
            let _seam = install_recorder(0);
            assert_eq!(counted_wstr_eq(a.as_ptr(), b.as_ptr(), 0x1f), 1);
            assert_eq!(CALLS.len(), 1);
            let call = &CALLS[0];
            assert_eq!(call.s1, a.as_ptr().add(1));
            assert_eq!(call.len1, 3);
            assert_eq!(call.s2, b.as_ptr().add(1));
            assert_eq!(call.len2, 3);
            assert_eq!(call.flags, 0x1f);
        }
    }

    /// `rsbs r0, r0, #1; movcc r0, #0`: 1 iff the compare returned
    /// exactly 0; every other value maps to 0, including the -1
    /// tri-state and any other nonzero (huge as unsigned).
    #[test]
    fn only_a_zero_compare_is_equal() {
        let _lock = COMPARE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let a: [u16; 2] = [1, 0x61];
        let b: [u16; 2] = [1, 0x62];
        unsafe {
            for (result, expect) in [(0, 1), (1, 0), (-1, 0), (2, 0), (i32::MIN, 0)] {
                let _seam = install_recorder(result);
                assert_eq!(counted_wstr_eq(a.as_ptr(), b.as_ptr(), 0), expect);
            }
        }
    }

    /// Zero counts still pass the payload pointers one element on.
    #[test]
    fn zero_counts_pass_advanced_payload_pointers() {
        let _lock = COMPARE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let a: [u16; 1] = [0];
        let b: [u16; 1] = [0];
        unsafe {
            let _seam = install_recorder(0);
            assert_eq!(counted_wstr_eq(a.as_ptr(), b.as_ptr(), 0), 1);
            let call = &CALLS[0];
            assert_eq!(call.s1, a.as_ptr().add(1));
            assert_eq!(call.len1, 0);
            assert_eq!(call.s2, b.as_ptr().add(1));
            assert_eq!(call.len2, 0);
        }
    }

    /// The header is a full unsigned `u16` count: 0xffff arrives as
    /// 65535, not sign-extended or clamped.
    #[test]
    fn counts_are_unsigned_u16() {
        let _lock = COMPARE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let a: [u16; 1] = [0xffff];
        let b: [u16; 1] = [1];
        unsafe {
            let _seam = install_recorder(1);
            assert_eq!(counted_wstr_eq(a.as_ptr(), b.as_ptr(), 0), 0);
            let call = &CALLS[0];
            assert_eq!(call.len1, 65535);
            assert_eq!(call.len2, 1);
        }
    }
}
