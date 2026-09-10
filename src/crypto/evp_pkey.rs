//! OpenSSL's `EVP_PKEY_free` — the reference-counted destructor of the
//! `EVP_PKEY` public-key wrapper in the OpenSSL copy Apple vendored into
//! retailOS (the SSLeay-era libcrypto whose BIO layer, object database
//! and bignum cluster are documented in this module's siblings).
//!
//! Port: `evp_pkey_free` — `FUN_0804ae6c` @ 0x0804ae6c (64 bytes,
//! 0x0804ae6c..0x0804aeab; the next separately linked function, the
//! 8-byte `mov r0, #0; bx lr` `EVP_PKEY_cmp_parameters`-style stub, sits
//! at 0x0804aeac, so Ghidra's 64-byte extent is exactly right). **15
//! call sites**, binary-verified by decoding every ARM B/BL word in
//! osos.dec: 12 unconditional `bl`, 2 `bleq` (0x080e8424, 0x080f4f68)
//! and 1 `blne` (0x082d4938) — the predicated three are caller-side
//! error-path gates, not NULL guards, because this function has its own
//! NULL check. No tail `b` sites, and no DATA word in the image holds
//! the address, so it is never dispatched virtually.
//!
//! # Decoded from the raw ARM at 0x0804ae6c
//!
//! ```text
//! push {r3, r4, r5, lr}
//! movs r4, r0
//! beq  0x0804aea8            ; if (x == NULL) return
//! mov  r3, #0
//! mov  r2, #10               ; CRYPTO_LOCK_EVP_PKEY
//! mvn  r1, #0                ; amount = -1
//! add  r0, r4, #8            ; &x->references
//! str  r3, [sp]              ; line = 0 (5th arg, stack)
//! bl   0x08043828            ; CRYPTO_add_lock(&x->references, -1, 10, NULL, 0)
//! cmp  r0, #0
//! bgt  0x0804aea8            ; still referenced: return
//! mov  r0, r4
//! bl   0x08093cbc            ; EVP_PKEY_free_it(x)
//! mov  r0, r4
//! bl   0x08043994            ; traced_free(x)  (OPENSSL_free)
//! pop  {r3, r4, r5, pc}
//! ```
//!
//! Sixteen instruction words, no literal pool. Upstream
//! crypto/evp/p_lib.c:
//! `void EVP_PKEY_free(EVP_PKEY *x) { if (x == NULL) return;
//! i = CRYPTO_add(&x->references, -1, CRYPTO_LOCK_EVP_PKEY);
//! if (i > 0) return; EVP_PKEY_free_it(x); OPENSSL_free(x); }`
//!
//! # Why this is OpenSSL's EVP layer
//!
//! The whole neighbourhood checks out against SSLeay/OpenSSL p_lib.c:
//!
//! - The constructor sibling @ 0x0804aeb4 (`EVP_PKEY_new`) allocates 24
//!   bytes through `traced_alloc` and stamps
//!   `{type = 0, references = 1, pkey = NULL, save_parameters = 1,
//!   attributes = NULL}` — field for field the 0.9.6-era `evp_pkey_st`
//!   — and reports failure with `0x08049a84(6, 106, 65, 0)`, i.e.
//!   `ERR_put_error(ERR_LIB_EVP=6, EVP_F_EVP_PKEY_NEW=106,
//!   ERR_R_MALLOC_FAILURE=65)`.
//! - The type normalizer @ 0x0804af30 maps {6, 19} -> 6, keeps 28,
//!   folds {66, 67, 70, 113, 116} -> 116 and returns 0 otherwise —
//!   exactly `EVP_PKEY_type`: {EVP_PKEY_RSA, EVP_PKEY_RSA2} -> RSA,
//!   EVP_PKEY_DH, {EVP_PKEY_DSA1..4, EVP_PKEY_DSA} -> DSA, else
//!   `NID_undef`.
//! - The size query @ 0x0804af10 is `type == EVP_PKEY_RSA ?
//!   RSA_size(x->pkey.rsa) : 0` (`EVP_PKEY_size`), its callee
//!   0x08063040 being `(BN_num_bits(rsa->n @ +0x10) + 7) / 8`.
//! - `CRYPTO_add_lock` @ 0x08043828 brackets its `*pointer += amount`
//!   in `resource_op_dispatch(9, type)` / `(10, type)` — the
//!   CRYPTO_LOCK/CRYPTO_UNLOCK pair — with a whole-operation override
//!   through services-descriptor slot +0x0c (the `add_lock_callback`),
//!   all NULL in the stock descriptor.
//! - `EVP_PKEY_free_it` @ 0x08093cbc handles only tags 6 and 19, tail-
//!   branching to 0x08062374(x->pkey.rsa) — `RSA_free`: refcount at
//!   +0x38 under `CRYPTO_LOCK_RSA = 9`, `rsa_meth_st.finish` at
//!   meth+0x20, `CRYPTO_free_ex_data(class 6 = RSA, rsa, &ex_data @
//!   +0x30)`, then eight `BN_free`s of n/e/d/p/q/dmp1/dmq1/iqmp @
//!   +0x10..+0x2c.
//!
//! # Deviations
//!
//! - `EVP_PKEY_free_it` @ 0x08093cbc is unported, so it rides the
//!   remaining [`EVP_PKEY_OPS`] seam: on target its default calls the
//!   stock body in place, while host tests install a recorder.
//! - `CRYPTO_add_lock` @ 0x08043828 is ported in [`super::add_lock`] and
//!   called directly, as in the original.
//! - `OPENSSL_free` is the ported [`traced_free`] @ 0x08043994, called
//!   directly like the original's `bl`.

use crate::drivers::ata_cmd::traced_free;
use crate::crypto::add_lock::crypto_add_lock;

/// `CRYPTO_LOCK_EVP_PKEY` — the lock class the reference decrement runs
/// under (the original's `mov r2, #10`).
pub const CRYPTO_LOCK_EVP_PKEY: i32 = 10;

/// OpenSSL `EVP_PKEY` (libcrypto 0.9.6-era `evp_pkey_st`, 24 bytes on
/// the 32-bit target). Field identity is fixed by the constructor @
/// 0x0804aeb4's stores and the sibling accessors documented in the
/// module header; host fixtures widen the two pointer fields, keeping
/// every field disjoint on a 64-bit host.
#[repr(C)]
pub struct EvpPkey {
    /// +0x00: `type` — an `EVP_PKEY_*` id (6 = RSA, 19 = RSA2, 28 = DH,
    /// 116 = DSA) as normalized by `EVP_PKEY_type` @ 0x0804af30.
    pub pkey_type: i32,
    /// +0x04: `save_type` — the caller's raw type argument, stored by
    /// the construct path @ 0x082c5834 before normalization.
    pub save_type: i32,
    /// +0x08: `references` — the intrusive count; 1 at construction,
    /// decremented here under `CRYPTO_LOCK_EVP_PKEY`. Teardown runs
    /// whenever the decremented value is not positive (the original's
    /// signed `bgt`), so an already-zero or negative count still frees.
    pub references: i32,
    /// +0x0c: the `pkey` union pointer (`RSA *` for types 6/19 — the
    /// only payloads `EVP_PKEY_free_it` @ 0x08093cbc releases).
    pub pkey: *mut u8,
    /// +0x10: `save_parameters` (constructor stores 1).
    pub save_parameters: i32,
    /// +0x14: `attributes` — `STACK_OF(X509_ATTRIBUTE) *` (constructor
    /// stores NULL).
    pub attributes: *mut u8,
}


/// Indirect dispatch for this destructor's unported `EVP_PKEY_free_it`
/// callee. On target the slot defaults to the stock body called in place;
/// host tests install a recorder.
#[derive(Copy, Clone)]
pub struct EvpPkeyOps {
    /// `EVP_PKEY_free_it` @ 0x08093cbc: releases the payload for types
    /// 6/19 (`RSA_free` @ 0x08062374) and is a no-op for every other type.
    pub free_it: unsafe extern "C" fn(pkey: *mut EvpPkey),
}


/// Target default: the stock `EVP_PKEY_free_it` @ 0x08093cbc, called in
/// place until it is ported.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_evp_pkey_free_it(pkey: *mut EvpPkey) {
    let worker: unsafe extern "C" fn(*mut EvpPkey) =
        unsafe { core::mem::transmute(0x0809_3cbcusize) };
    unsafe { worker(pkey) }
}


/// Host default: nothing to forward to, and a silent no-op would hide a
/// missing install by leaking the payload.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_evp_pkey_free_it(_pkey: *mut EvpPkey) {
    panic!("evp_pkey_free requires the EVP_PKEY_free_it worker 0x08093cbc")
}

/// The active unported callee. Host tests install a recording mock.
#[cfg(target_os = "none")]
pub static mut EVP_PKEY_OPS: EvpPkeyOps = EvpPkeyOps {
    free_it: firmware_evp_pkey_free_it,
};

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut EVP_PKEY_OPS: EvpPkeyOps = EvpPkeyOps {
    free_it: missing_evp_pkey_free_it,
};

/// Reads the remaining unported callee. Volatile so a build in which
/// nothing rewrites the table cannot constant-fold the default in and
/// delete the dispatch (house rule, see crypto/bn_num_bits.rs).
#[inline(always)]
fn evp_pkey_ops() -> EvpPkeyOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVP_PKEY_OPS)) }
}

/// evp_pkey_free — original: `FUN_0804ae6c` @ 0x0804ae6c (64 bytes; 15
/// call sites — 12 `bl`, 2 `bleq`, 1 `blne` — binary-verified).
///
/// OpenSSL `EVP_PKEY_free`: a NULL `pkey` returns untouched. Otherwise
/// drop one reference under `CRYPTO_LOCK_EVP_PKEY`; when the key is
/// still referenced (decremented count > 0, signed), return. On the
/// final drop run `EVP_PKEY_free_it` to release the payload, then free
/// the 24-byte wrapper through [`traced_free`]. The teardown gate is
/// signed, so a count that was already zero or negative wraps downward
/// and still destroys the key — exactly the original's `cmp r0, #0` /
/// `bgt`.
///
/// # Safety
///
/// payload is owned by it. The `EVP_PKEY_free_it` slot in
/// [`EVP_PKEY_OPS`] must be installed on host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn evp_pkey_free(pkey: *mut EvpPkey) {
    if pkey.is_null() {
        return;
    }
    let remaining =
        crypto_add_lock(core::ptr::addr_of_mut!((*pkey).references), -1, CRYPTO_LOCK_EVP_PKEY, core::ptr::null(), 0);
    let ops = evp_pkey_ops();
    if remaining > 0 {
        return;
    }
    (ops.free_it)(pkey);
    traced_free(pkey.cast::<u8>());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK, TracedFreeHooks};
    use crate::kernel::resource_op::RESOURCE_OP_HOOKS_TEST_LOCK;
    use parking_lot::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes swaps of [`EVP_PKEY_OPS`], [`TRACED_FREE_HOOKS`], and
    /// the shared resource-operation table `crypto_add_lock` reads.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// One recorded teardown callee invocation, in call order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        /// `EVP_PKEY_free_it(pkey)`.
        FreeIt(usize),
        /// The free slot inside `traced_free` running on the wrapper.
        Freed(usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }


    unsafe extern "C" fn recording_free_it(pkey: *mut EvpPkey) {
        unsafe { (*core::ptr::addr_of_mut!(EVENTS)).push(Event::FreeIt(pkey as usize)) };
    }

    unsafe extern "C" fn recording_free(block: *mut u8) {
        unsafe { (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Freed(block as usize)) };
    }

    /// Restores both shipped tables even when a test panics.
    struct OpsGuard {
        #[allow(dead_code)]
        ops: MutexGuard<'static, ()>,
        #[allow(dead_code)]
        resource: MutexGuard<'static, ()>,
        #[allow(dead_code)]
        free: parking_lot::MutexGuard<'static, ()>,
        saved_ops: EvpPkeyOps,
        saved_free: TracedFreeHooks,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(EVP_PKEY_OPS).write(self.saved_ops);
                core::ptr::addr_of_mut!(TRACED_FREE_HOOKS).write(self.saved_free);
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
            }
        }
    }

    fn install() -> OpsGuard {
        let resource = RESOURCE_OP_HOOKS_TEST_LOCK.lock();
        let ops = OPS_LOCK.lock();
        let free = TRACED_FREE_TEST_LOCK.lock();
        let guard = OpsGuard {
            ops,
            resource,
            free,
            saved_ops: unsafe { core::ptr::addr_of!(EVP_PKEY_OPS).read() },
            saved_free: unsafe { core::ptr::addr_of!(TRACED_FREE_HOOKS).read() },
        };
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::addr_of_mut!(EVP_PKEY_OPS).write(EvpPkeyOps {
                free_it: recording_free_it,
            });
            core::ptr::addr_of_mut!(TRACED_FREE_HOOKS).write(TracedFreeHooks {
                free: recording_free,
                trace: None,
            });
        }
        guard
    }

    fn key(pkey_type: i32, references: i32, payload: *mut u8) -> EvpPkey {
        EvpPkey {
            pkey_type,
            save_type: pkey_type,
            references,
            pkey: payload,
            save_parameters: 1,
            attributes: core::ptr::null_mut(),
        }
    }

    #[test]
    fn null_key_is_a_no_op() {
        // The original's `movs r4, r0 / beq` fires before any callee:
        // no lock operation, no payload release, no free.
        let _guard = install();

        unsafe { evp_pkey_free(core::ptr::null_mut()) };

        assert!(events().is_empty(), "a NULL key must not touch any callee");
    }

    #[test]
    fn shared_key_only_drops_one_reference() {
        let _guard = install();
        let mut k = key(6, 2, core::ptr::null_mut());

        unsafe { evp_pkey_free(core::ptr::addr_of_mut!(k)) };
        assert_eq!(k.references, 1, "one reference dropped under lock class 10");

        assert!(events().is_empty(), "the shared key takes no teardown callee");
    }

    #[test]
    fn last_reference_releases_the_payload_then_frees_the_wrapper() {
        let _guard = install();
        let mut k = key(6, 1, 0xdead_beefusize as *mut u8);
        let at = core::ptr::addr_of_mut!(k) as usize;

        unsafe { evp_pkey_free(core::ptr::addr_of_mut!(k)) };

        assert_eq!(k.references, 0);
        assert_eq!(
            events(),
            std::vec![
                Event::FreeIt(at),
                Event::Freed(at),
            ],
            "free_it runs on the wrapper before traced_free does"
        );
    }

    #[test]
    fn nonpositive_counts_still_destroy_the_key() {
        // The teardown gate is the signed `cmp r0, #0 / bgt`: counts of
        // 0 and -7 wrap downward (0 -> -1, -7 -> -8) and STILL free.
        let _guard = install();
        for start in [0, -7] {
            unsafe { (*core::ptr::addr_of_mut!(EVENTS)).clear() };
            let mut k = key(19, start, core::ptr::null_mut());
            let at = core::ptr::addr_of_mut!(k) as usize;

            unsafe { evp_pkey_free(core::ptr::addr_of_mut!(k)) };

            assert_eq!(k.references, start - 1, "count {start} wraps downward");
            assert_eq!(
                events(),
                std::vec![
                    Event::FreeIt(at),
                    Event::Freed(at),
                ],
                "a nonpositive decremented count takes the teardown path"
            );
        }
    }

}
