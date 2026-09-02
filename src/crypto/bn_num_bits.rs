//! OpenSSL's `BN_num_bits` — the bit-length query of the `BIGNUM`
//! type in the OpenSSL copy Apple vendored into retailOS (the
//! SSLeay-era libcrypto whose BIO layer and object database are
//! documented in this module's siblings).
//!
//! Port: `bn_num_bits` — `FUN_080404a8` @ 0x080404a8 (52 bytes,
//! 0x080404a8..0x080404dc; **22 call sites**, binary-verified by
//! decoding every ARM B/BL word in osos.dec: all 22 are unconditional
//! `bl` — no predicated forms, no tail branches, so no caller
//! NULL-guards or flag-gates this entry point. No DATA word in the
//! image holds the address, so it is never dispatched virtually).
//!
//! # Decoded from the raw ARM at 0x080404a8
//!
//! ```text
//! push {lr}
//! ldr   r1, [r0, #4]      ; r1 = a->top
//! cmp   r1, #0
//! moveq r0, #0            ; BN_is_zero(a)  ->  return 0
//! popeq {pc}
//! ldr   r0, [r0]          ; r0 = a->d
//! add   r0, r0, r1, lsl #2
//! sub   r1, r1, #1        ; i = top - 1
//! ldr   r0, [r0, #-4]     ; r0 = a->d[i]   (the most significant limb)
//! lsl   r3, r1, #5        ; i * BN_BITS2   (BN_BITS2 = 32)
//! bl    0x080404dc        ; BN_num_bits_word(limb)
//! add   r0, r0, r3        ; i*32 + bits-in-top-limb
//! pop   {pc}
//! ```
//!
//! Thirteen words, no literal pool of its own; the next entry is the
//! callee `BN_num_bits_word` @ 0x080404dc itself (a separately linked
//! function with its own callers), so Ghidra's 52-byte extent is
//! exactly right. Upstream crypto/bn/bn_lib.c:
//! `int BN_num_bits(const BIGNUM *a) { int i = a->top - 1;
//! if (BN_is_zero(a)) return 0;
//! return ((i * BN_BITS2) + BN_num_bits_word(a->d[i])); }` — the
//! `bn_check_top` assert is compiled out.
//!
//! # Why this is OpenSSL's BN layer
//!
//! The surrounding cluster 0x0803d800..0x08041000 operates on
//! `{ BN_ULONG *d; int top; int dmax; int neg; int flags }` — the
//! OpenSSL `BIGNUM` (the multiplier @ 0x080400b0 EORs the `neg` words
//! @ +0x0c of both operands into the result's, tests `flags` @ +0x10
//! against 2 = `BN_FLG_STATIC_DATA`). The callee @ 0x080404dc is
//! bn_lib.c's `BN_num_bits_word`, a most-significant-nonzero-byte
//! select feeding a 256-byte `bits[]` table whose literal pool word @
//! 0x08040514 is 0x08906520. Callers binary-confirm the identity:
//! `FUN_08063040` @ 0x08063040 is `(BN_num_bits(a) + 7) / 8` —
//! `BN_num_bytes` — and `FUN_082d48ac` @ 0x082d48ac (X.509 chain
//! walk) requires `BN_num_bits(key) == 0x400`, the RSA-1024 modulus
//! check.
//!
//! # The bits[] table anomaly
//!
//! `BN_num_bits_word`'s table base 0x08906520 lands in the middle of
//! the Italian UI string heap at rest (file offset 0x890520 is
//! `"tata.\0"` inside `"...non è più supportata."`; `"Hong Kong"` @
//! 0x08906148 and friends are referenced as strings from live code).
//! No instruction writes a table there, and no canonical
//! `{0,1,2,2,3,3,3,3,...}` byte run exists anywhere in osos.dec, so
//! the runtime content of 0x08906520 must be installed by a loader
//! pass this port does not model — or every `BN_num_bits` call would
//! return string bytes. Documented, not explained: the port reaches
//! the helper through the [`BN_NUM_BITS_WORD`] slot, whose target
//! default calls the stock 0x080404dc in place, so device behavior is
//! bit-exact whatever lives at 0x08906520.
//!
//! Helper semantics, for whoever ports 0x080404dc: select the most
//! significant nonzero byte of the limb, return `bits[byte] + 8*k`
//! (k = byte index 0..3); for limb == 0 it returns `bits[0]`.
//! Upstream `bits[b] = floor(log2(b)) + 1` (bit length of the byte,
//! `bits[0] = 0`), so the helper yields the limb's bit length 1..=32
//! and `BN_num_bits` the bignum's total bit length — consistent with
//! the RSA-1024 `== 0x400` caller (top = 32 limbs, top limb length 32
//! gives 31*32 + 32 = 1024) and with `bits[0] = 0` making a zero top
//! limb contribute nothing.
//!
//! # Deviations
//!
//! - `BN_num_bits_word` @ 0x080404dc is not ported yet, so it rides
//!   the [`BN_NUM_BITS_WORD`] slot: on target the default calls
//!   0x080404dc in place (the original `bl` becomes a volatile slot
//!   load plus `blx`, the same documented seam shape as
//!   crypto/bio_printf.rs); on host it panics until a test installs
//!   one.
//! - The top-limb index arithmetic is `wrapping_*` so a bogus
//!   `top < 0` cannot trip host overflow checks; on target the
//!   wrapping ops are the same single `sub`/`lsl` the original emits.

/// OpenSSL `BIGNUM` (libcrypto, 32-bit `BN_ULONG`). Only `d` and
/// `top` are read here; `dmax`/`neg`/`flags` complete the layout the
/// neighboring multiplier (`neg` @ +0x0c) and callers use.
#[repr(C)]
pub struct BigNum {
    /// Limb storage, least significant limb first.
    pub d: *const u32,
    /// Number of limbs in use; `top == 0` is `BN_is_zero`.
    pub top: i32,
    /// Allocated limb capacity (`dmax` upstream).
    pub dmax: i32,
    /// Sign flag (`neg` upstream); EORed by the multiplier.
    pub neg: i32,
    /// `BN_FLG_*` bits (`BN_FLG_STATIC_DATA` = 2 observed).
    pub flags: i32,
}

/// The limb bit-length worker's signature: one limb in, its bit
/// length (1..=32, or `bits[0]` for 0) out.
pub type BnNumBitsWordFn = unsafe extern "C" fn(limb: u32) -> i32;

/// Target default: the stock `BN_num_bits_word` @ 0x080404dc, called
/// in place until it is ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_num_bits_word(limb: u32) -> i32 {
    let worker: BnNumBitsWordFn = unsafe { core::mem::transmute(0x0804_04dcusize) };
    unsafe { worker(limb) }
}

/// Host default: nothing to forward to, and silently returning 0
/// would make a missing install look like a zero-length limb.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_num_bits_word(_limb: u32) -> i32 {
    panic!("bn_num_bits requires the BN_num_bits_word worker 0x080404dc")
}

/// The active `BN_num_bits_word` worker. Host tests install recording
/// mocks.
#[cfg(target_os = "none")]
pub static mut BN_NUM_BITS_WORD: BnNumBitsWordFn = firmware_bn_num_bits_word;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut BN_NUM_BITS_WORD: BnNumBitsWordFn = missing_bn_num_bits_word;

/// Reads the worker slot. Volatile so a build in which nothing
/// rewrites the slot cannot constant-fold the default in and delete
/// the dispatch (house rule, see stdio/semihost.rs).
#[inline(always)]
unsafe fn bn_num_bits_word() -> BnNumBitsWordFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_NUM_BITS_WORD)) }
}

/// bn_num_bits — original: `FUN_080404a8` @ 0x080404a8 (52 bytes; 22
/// call sites, all unconditional `bl` — binary-verified).
///
/// OpenSSL `BN_num_bits`: 0 for a zero bignum (`top == 0`, the only
/// early-out — `d` is never dereferenced on that path), otherwise
/// `(top - 1) * 32 + BN_num_bits_word(d[top - 1])`, the bit length of
/// the value. Nothing is validated: a NULL `a` faults exactly as in
/// the original, and no caller gates the call (all 22 sites are
/// unconditional).
///
/// # Safety
///
/// `a` must name a live [`BigNum`] whose `d` buffer holds at least
/// `top` readable limbs. [`BN_NUM_BITS_WORD`] must be installed on
/// host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_num_bits(a: *const BigNum) -> i32 {
    let top = (*a).top;
    if top == 0 {
        return 0;
    }
    let i = top.wrapping_sub(1);
    let last = (*a).d.wrapping_add(i as usize).read();
    unsafe { (bn_num_bits_word())(last) + (i << 5) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes swaps of [`BN_NUM_BITS_WORD`].
    static WORKER_LOCK: Mutex<()> = Mutex::new(());

    /// Limbs the recording worker saw, in order.
    static mut SEEN: Vec<u32> = Vec::new();
    /// Results the recorder returns, one per call, then repeating the last.
    static mut RESULTS: Vec<i32> = Vec::new();

    unsafe extern "C" fn recording_bits_word(limb: u32) -> i32 {
        unsafe {
            let seen = &mut *core::ptr::addr_of_mut!(SEEN);
            seen.push(limb);
            let results = &*core::ptr::addr_of!(RESULTS);
            results[(seen.len() - 1).min(results.len() - 1)]
        }
    }

    /// The upstream bits[] table's semantics: bit length of the most
    /// significant nonzero byte plus 8 * its index.
    unsafe extern "C" fn openssl_bits_word(limb: u32) -> i32 {
        if limb == 0 {
            0
        } else {
            (32 - limb.leading_zeros()) as i32
        }
    }

    /// Restores the shipped default even when a test panics.
    struct WorkerGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BN_NUM_BITS_WORD).write(missing_bn_num_bits_word);
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
            core::ptr::addr_of_mut!(BN_NUM_BITS_WORD).write(recording_bits_word);
        }
        WorkerGuard(guard)
    }

    fn install_openssl() -> WorkerGuard {
        let guard = WORKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(BN_NUM_BITS_WORD).write(openssl_bits_word);
        }
        WorkerGuard(guard)
    }

    fn seen() -> Vec<u32> {
        unsafe { (*core::ptr::addr_of!(SEEN)).clone() }
    }

    fn bignum(d: *const u32, top: i32) -> BigNum {
        BigNum { d, top, dmax: top, neg: 0, flags: 0 }
    }

    #[test]
    fn zero_top_returns_zero_without_touching_the_worker_or_the_limbs() {
        // BN_is_zero is `top == 0` alone: the original's `moveq/popeq`
        // fires before `d` is loaded, so a NULL limb buffer is fine
        // and BN_num_bits_word is never entered.
        let _guard = install(&[99]);
        let a = bignum(core::ptr::null(), 0);

        let rc = unsafe { bn_num_bits(&a) };

        assert_eq!(rc, 0);
        assert!(seen().is_empty(), "the worker must not run for top == 0");
    }

    #[test]
    fn queries_the_most_significant_limb_only() {
        let _guard = install(&[7]);
        let limbs = [0xdead_beefu32, 0x1234_5678, 0x0000_00ff];
        let a = bignum(limbs.as_ptr(), 3);

        let rc = unsafe { bn_num_bits(&a) };

        assert_eq!(seen(), std::vec![0x0000_00ff], "d[top - 1], and nothing else");
        assert_eq!(rc, 7 + 64, "(top - 1) * BN_BITS2 scales the worker result");
    }

    #[test]
    fn single_limb_bignum_passes_it_unscaled() {
        let _guard = install(&[1]);
        let limbs = [1u32];
        let a = bignum(limbs.as_ptr(), 1);

        let rc = unsafe { bn_num_bits(&a) };

        assert_eq!(seen(), std::vec![1]);
        assert_eq!(rc, 1, "i = 0 contributes no limb offset");
    }

    #[test]
    fn re_reads_the_worker_slot_on_every_call() {
        let _guard = install(&[3, 8]);
        let limbs = [0x10u32, 0x20];
        let a = bignum(limbs.as_ptr(), 2);

        let first = unsafe { bn_num_bits(&a) };
        let second = unsafe { bn_num_bits(&a) };

        assert_eq!((first, second), (3 + 32, 8 + 32), "nothing is cached between calls");
        assert_eq!(seen(), std::vec![0x20, 0x20]);
    }

    #[test]
    fn matches_openssl_semantics_end_to_end() {
        // With the worker behaving as the upstream bits[] table
        // (32 - clz), the composition is the textbook bit length.
        let _guard = install_openssl();

        // The FUN_082d48ac contract: an RSA-1024 modulus — 32 limbs,
        // top limb's MSB set — measures exactly 0x400.
        let mut modulus = [0u32; 32];
        modulus[31] = 0x8000_0000;
        let a = bignum(modulus.as_ptr(), 32);
        assert_eq!(unsafe { bn_num_bits(&a) }, 0x400);

        // Full top limb still measures 1024; one bit less does not.
        modulus[31] = 0xffff_ffff;
        let a = bignum(modulus.as_ptr(), 32);
        assert_eq!(unsafe { bn_num_bits(&a) }, 0x400);
        modulus[31] = 0x4000_0000;
        let a = bignum(modulus.as_ptr(), 32);
        assert_eq!(unsafe { bn_num_bits(&a) }, 0x3ff);

        // Value 1: a single limb of length 1.
        let limbs = [1u32];
        let a = bignum(limbs.as_ptr(), 1);
        assert_eq!(unsafe { bn_num_bits(&a) }, 1);

        // A zero top limb contributes nothing (bits[0] == 0 upstream):
        // the original's helper reads table[0] for limb 0 and adds it.
        let limbs = [0xffff_ffffu32, 0];
        let a = bignum(limbs.as_ptr(), 2);
        assert_eq!(unsafe { bn_num_bits(&a) }, 32);
    }
}
