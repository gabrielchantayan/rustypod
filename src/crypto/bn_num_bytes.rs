//! OpenSSL's `RSA_size` — byte length of an RSA modulus.
//!
//! Port: `rsa_size` — `FUN_08063040` at load address **0x08063040**
//! (**32 bytes**, 0x08063040..0x08063060; the next real entry starts with
//! `push {r1-r11,lr}`). Raw ARM decoding finds **three inbound plain `bl`
//! call sites and zero predicated `bl` call sites**; its one outbound call is
//! an unconditional `bl` to [`bn_num_bits`]. It reads `rsa->n` from target
//! word offset +0x10, obtains its bit length, adds seven with ARM wrapping
//! arithmetic, then signed-divides by eight toward zero. Deliberate deviation:
//! Rust's signed division expresses the original add/sign-adjust/arithmetic-
//! shift sequence; `wrapping_add` preserves ARM overflow behavior.

use super::bn_num_bits::{bn_num_bits, BigNum};

/// OpenSSL `RSA_size` — original `FUN_08063040` at load address **0x08063040**
/// (32 bytes; three plain `bl` callers, no predicated calls).
///
/// `rsa` is target-width storage: its word at byte offset 0x10 is the 32-bit
/// pointer to the modulus `BIGNUM`. Word indexing avoids treating an x86-64
/// host pointer as an ARM field.
///
/// # Safety
///
/// `rsa` must name a live target-layout RSA object with a valid `BIGNUM` at
/// word 4. The retail function has no NULL checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rsa_size(rsa: *const u32) -> i32 {
    let modulus = unsafe { rsa.add(4).read() as usize as *const BigNum };
    unsafe { bn_num_bits(modulus) }.wrapping_add(7) / 8
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::rsa_size;
    use crate::crypto::bn_num_bits::{BigNum, BnNumBitsWordFn, BN_NUM_BITS_WORD, BN_NUM_BITS_WORD_TEST_LOCK};
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use parking_lot::MutexGuard;

    unsafe extern "C" fn openssl_bits_word(limb: u32) -> i32 {
        if limb == 0 { 0 } else { (32 - limb.leading_zeros()) as i32 }
    }

    struct WorkerGuard {
        saved: BnNumBitsWordFn,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(BN_NUM_BITS_WORD).write(self.saved) };
        }
    }

    fn install_openssl_worker() -> WorkerGuard {
        let lock = BN_NUM_BITS_WORD_TEST_LOCK.lock();
        let saved = unsafe { ptr::read_volatile(ptr::addr_of!(BN_NUM_BITS_WORD)) };
        unsafe { ptr::addr_of_mut!(BN_NUM_BITS_WORD).write(openssl_bits_word) };
        WorkerGuard { saved, _lock: lock }
    }

    fn rsa_with_modulus(slab: *mut u8, limbs: &[u32]) -> *const u32 {
        let rsa = slab.cast::<u32>();
        let modulus = unsafe { slab.add(0x40).cast::<BigNum>() };
        unsafe {
            modulus.write(BigNum { d: limbs.as_ptr(), top: limbs.len() as i32, dmax: limbs.len() as i32, neg: 0, flags: 0 });
            rsa.add(4).write(modulus as usize as u32);
        }
        rsa
    }

    #[test]
    fn zero_modulus_top_returns_zero() {
        let Some(slab) = try_map_u32_slab(hints::RSA_SIZE, 0x1000) else { return };
        let _worker = install_openssl_worker();
        assert_eq!(unsafe { rsa_size(rsa_with_modulus(slab, &[])) }, 0);
    }

    #[test]
    fn rounds_modulus_bit_lengths_to_complete_bytes() {
        let Some(slab) = try_map_u32_slab(hints::RSA_SIZE, 0x1000) else { return };
        let _worker = install_openssl_worker();
        for &(limb, expected) in &[(1, 1), (0x80, 1), (0x100, 2), (0xffff_ffff, 4)] {
            assert_eq!(unsafe { rsa_size(rsa_with_modulus(slab, &[limb])) }, expected);
        }
    }

    #[test]
    fn includes_all_lower_modulus_limbs() {
        let Some(slab) = try_map_u32_slab(hints::RSA_SIZE, 0x1000) else { return };
        let _worker = install_openssl_worker();
        assert_eq!(unsafe { rsa_size(rsa_with_modulus(slab, &[0, 0x80])) }, 5);
    }
}
