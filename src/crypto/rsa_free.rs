//! OpenSSL's `RSA_free` destructor.
//!
//! Port: `rsa_free` — `FUN_08062374` @ `0x08062374` (212 bytes,
//! `0x08062374..0x08062447`; the next separately linked function begins at
//! `0x08062448`). **3 unconditional `bl` call sites and 11 predicated calls**
//! in the body: one `blxne` method `finish`, eight `blne`
//! `tagged_word_buffer_destroy`, one `blne` `two_buffer_owner_release`, and
//! one `blne` alternate allocator release. The three direct calls are
//! `crypto_add_lock`, `crypto_free_ex_data`, and `traced_free`.
//!
//! # Algorithm
//!
//! NULL returns. Otherwise decrement `references` (+0x38) under
//! `CRYPTO_LOCK_RSA = 9`; only a signed positive result retains ownership.
//! On the final drop, invoke `rsa_meth_st.finish` (+0x08 in the method table)
//! when present, release RSA ex-data (+0x30), destroy the eight tagged BIGNUM
//! buffers at +0x10..+0x2c in ascending order, then release the optional
//! montgomery and blinding-owner fields (+0x50 and +0x4c) before freeing RSA.
//!
//! # Deliberate deviations
//!
//! Target code directly calls the already-ported helpers and dynamically loads
//! the method-table function word. The unported `FUN_08043a20` target remains
//! an address call. Host code uses `RSA_FREE_OPS`: host pointers are wider than
//! retailOS target words, so this preserves target offsets while letting tests
//! observe each target call without fabricating 32-bit mappings.

use core::ffi::c_void;

use crate::crypto::add_lock::crypto_add_lock;

/// `CRYPTO_LOCK_RSA`, loaded as `mov r2, #9` by retailOS.
pub const CRYPTO_LOCK_RSA: i32 = 9;

/// Host dispatch for the target-word destructor calls.
#[cfg(not(target_os = "none"))]
#[derive(Copy, Clone)]
pub struct RsaFreeOps {
    pub finish: unsafe extern "C" fn(u32),
    pub free_ex_data: unsafe extern "C" fn(i32, u32, u32),
    pub destroy_tagged_word_buffer: unsafe extern "C" fn(u32),
    pub release_two_buffer_owner: unsafe extern "C" fn(u32),
    pub release_blinding: unsafe extern "C" fn(u32),
    pub traced_free: unsafe extern "C" fn(u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_rsa_free_op() {
    panic!("rsa_free requires installed host RSA_FREE_OPS")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_finish(_rsa: u32) { unsafe { missing_rsa_free_op() } }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_free_ex_data(_class: i32, _rsa: u32, _ex_data: u32) { unsafe { missing_rsa_free_op() } }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_object: u32) { unsafe { missing_rsa_free_op() } }

/// Active host model of the method and teardown calls.
#[cfg(not(target_os = "none"))]
pub static mut RSA_FREE_OPS: RsaFreeOps = RsaFreeOps {
    finish: missing_finish,
    free_ex_data: missing_free_ex_data,
    destroy_tagged_word_buffer: missing_release,
    release_two_buffer_owner: missing_release,
    release_blinding: missing_release,
    traced_free: missing_release,
};

#[cfg(test)]
pub static RSA_FREE_OPS_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn rsa_free_ops() -> RsaFreeOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RSA_FREE_OPS)) }
}

/// Releases a retailOS `RSA` object represented as 32-bit target words.
///
/// # Safety
/// `rsa` must be null or address at least 21 target words with the retailOS
/// RSA layout. On target, every nonzero pointed-to object and method slot must
/// satisfy its original destructor contract. Host callers must install
/// [`RSA_FREE_OPS`] before a final reference drop.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rsa_free(rsa: *mut u32) {
    if rsa.is_null() {
        return;
    }
    let remaining = unsafe {
        crypto_add_lock(rsa.add(14).cast::<i32>(), -1, CRYPTO_LOCK_RSA, core::ptr::null(), 0)
    };
    if remaining > 0 {
        return;
    }

    #[cfg(target_os = "none")]
    unsafe {
        let method = core::ptr::read_volatile(rsa.add(2));
        let finish_word = core::ptr::read_volatile((method as usize as *const u32).add(8));
        if finish_word != 0 {
            let finish: unsafe extern "C" fn(*mut u32) = core::mem::transmute(finish_word as usize);
            finish(rsa);
        }
        crate::crypto::free_ex_data::crypto_free_ex_data(6, rsa.cast::<c_void>(), rsa.add(12).cast::<c_void>());
        for field in 4..12 {
            let buffer = core::ptr::read_volatile(rsa.add(field));
            if buffer != 0 {
                crate::heap::tagged_word_buffer::tagged_word_buffer_destroy(buffer as usize as *mut crate::heap::tagged_word_buffer::TaggedWordBuffer);
            }
        }
        let montgomery = core::ptr::read_volatile(rsa.add(20));
        if montgomery != 0 {
            crate::heap::two_buffer_owner::two_buffer_owner_release(montgomery as usize as *mut crate::heap::two_buffer_owner::TwoBufferOwner);
        }
        let blinding = core::ptr::read_volatile(rsa.add(19));
        if blinding != 0 {
            let release_blinding: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0804_3a20usize);
            release_blinding(blinding as usize as *mut u8);
        }
        crate::drivers::ata_cmd::traced_free(rsa.cast::<u8>());
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        let ops = rsa_free_ops();
        if *rsa.add(2) != 0 {
            (ops.finish)(rsa as usize as u32);
        }
        (ops.free_ex_data)(6, rsa as usize as u32, rsa.add(12) as usize as u32);
        for field in 4..12 {
            let buffer = *rsa.add(field);
            if buffer != 0 {
                (ops.destroy_tagged_word_buffer)(buffer);
            }
        }
        let montgomery = *rsa.add(20);
        if montgomery != 0 {
            (ops.release_two_buffer_owner)(montgomery);
        }
        let blinding = *rsa.add(19);
        if blinding != 0 {
            (ops.release_blinding)(blinding);
        }
        (ops.traced_free)(rsa as usize as u32);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::MutexGuard;
    use std::vec::Vec;

    static mut EVENTS: Vec<(u8, u32)> = Vec::new();

    unsafe extern "C" fn finish(rsa: u32) { unsafe { EVENTS.push((1, rsa)) } }
    unsafe extern "C" fn free_ex_data(_class: i32, rsa: u32, _ex_data: u32) { unsafe { EVENTS.push((2, rsa)) } }
    unsafe extern "C" fn destroy(buffer: u32) { unsafe { EVENTS.push((3, buffer)) } }
    unsafe extern "C" fn release(owner: u32) { unsafe { EVENTS.push((4, owner)) } }
    unsafe extern "C" fn blinding_free(block: u32) { unsafe { EVENTS.push((5, block)) } }
    unsafe extern "C" fn free(block: u32) { unsafe { EVENTS.push((6, block)) } }

    struct Guard { _lock: MutexGuard<'static, ()>, saved: RsaFreeOps }
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RSA_FREE_OPS).write(self.saved);
                EVENTS.clear();
            }
        }
    }
    fn install() -> Guard {
        let lock = RSA_FREE_OPS_TEST_LOCK.lock();
        let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RSA_FREE_OPS)) };
        unsafe {
            core::ptr::addr_of_mut!(RSA_FREE_OPS).write(RsaFreeOps {
                finish, free_ex_data, destroy_tagged_word_buffer: destroy,
                release_two_buffer_owner: release, release_blinding: blinding_free, traced_free: free,
            });
            EVENTS.clear();
        }
        Guard { _lock: lock, saved }
    }

    #[test]
    fn null_and_shared_references_do_not_teardown() {
        let _guard = install();
        unsafe { rsa_free(core::ptr::null_mut()) };
        let mut rsa = [0u32; 21];
        rsa[14] = 2;
        unsafe { rsa_free(rsa.as_mut_ptr()) };
        assert_eq!(rsa[14], 1);
        assert!(unsafe { EVENTS.is_empty() });
    }

    #[test]
    fn final_drop_observes_retail_teardown_order() {
        let _guard = install();
        let mut rsa = [0u32; 21];
        rsa[2] = 0x1000;
        rsa[4] = 0x11;
        rsa[7] = 0x22;
        rsa[11] = 0x33;
        rsa[19] = 0x44;
        rsa[20] = 0x55;
        rsa[14] = 1;
        let rsa_word = rsa.as_mut_ptr() as usize as u32;
        unsafe { rsa_free(rsa.as_mut_ptr()) };
        assert_eq!(rsa[14], 0);
        assert_eq!(unsafe { EVENTS.as_slice() }, &[
            (1, rsa_word), (2, rsa_word), (3, 0x11), (3, 0x22), (3, 0x33),
            (4, 0x55), (5, 0x44), (6, rsa_word),
        ]);
    }
}
