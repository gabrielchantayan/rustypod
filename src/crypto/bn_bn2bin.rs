//! OpenSSL's `BN_bn2bin` — materializes a `BIGNUM` as big-endian bytes.
//!
//! Port: `bn_bn2bin` — `FUN_0803e3e0` at load address **0x0803e3e0**
//! (**88 bytes**, 0x0803e3e0..0x0803e438; the separately linked
//! `FUN_0803e438` opens immediately afterward). Binary-verifying every ARM
//! B/BL word in `osos.dec` finds **six** incoming calls: all are unconditional
//! `bl`, with no predicated calls or tail branches. The function calls
//! [`bn_num_bits`], rounds `(bits + 7)` by signed division toward zero, then
//! writes that many bytes from the least-significant-limb-first `BIGNUM` in
//! reverse byte order. It returns the byte count unchanged; Ghidra incorrectly
//! declares the function `void` even though `r0` retains that count.
//!
//! The retail body has no NULL, capacity, or normalized-top guard. In
//! particular, it does not dereference either input when `bn_num_bits` returns
//! zero or negative. The only deliberate porting deviation is inherited from
//! [`bn_num_bits`]: its unported `BN_num_bits_word` worker uses the documented
//! target seam, while host tests install an OpenSSL-semantic worker.

use super::bn_num_bits::{bn_num_bits, BigNum};

/// OpenSSL `BN_bn2bin` — original `FUN_0803e3e0` at load address
/// **0x0803e3e0** (88 bytes; six unconditional `bl` callers,
/// binary-verified).
///
/// Returns the byte length of `a`, and writes its magnitude most-significant
/// byte first to `to`. `a->d` remains little-endian limbs: byte `i` comes from
/// `a->d[i / 4] >> ((i % 4) * 8)`, while retail's countdown writes higher
/// `i` values first.
///
/// # Safety
///
/// `a` must name a live [`BigNum`] accepted by [`bn_num_bits`]. When the
/// returned byte count is positive, `to` must name that many writable bytes
/// and `a->d` must hold every limb selected by those byte indices. Like the
/// retail function, this validates none of these conditions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_bn2bin(a: *const BigNum, mut to: *mut u8) -> i32 {
    let byte_count = unsafe { bn_num_bits(a) }.wrapping_add(7) / 8;
    if byte_count <= 0 {
        return byte_count;
    }

    let mut byte_index = byte_count - 1;
    loop {
        let word = unsafe { (*a).d.add((byte_index / 4) as usize).read() };
        unsafe { to.write((word >> ((byte_index % 4) * 8)) as u8) };
        if byte_index == 0 {
            return byte_count;
        }
        byte_index -= 1;
        to = unsafe { to.add(1) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::bn_bn2bin;
    use crate::crypto::bn_num_bits::{BigNum, BnNumBitsWordFn, BN_NUM_BITS_WORD, BN_NUM_BITS_WORD_TEST_LOCK};
    use core::ptr;
    use parking_lot::MutexGuard;

    unsafe extern "C" fn openssl_bits_word(limb: u32) -> i32 {
        if limb == 0 {
            0
        } else {
            (32 - limb.leading_zeros()) as i32
        }
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

    fn bignum(limbs: &[u32]) -> BigNum {
        BigNum { d: limbs.as_ptr(), top: limbs.len() as i32, dmax: limbs.len() as i32, neg: 0, flags: 0 }
    }

    #[test]
    fn zero_value_returns_zero_without_dereferencing_output() {
        let _worker = install_openssl_worker();
        let zero = BigNum { d: ptr::null(), top: 0, dmax: 0, neg: 0, flags: 0 };

        assert_eq!(unsafe { bn_bn2bin(&zero, ptr::null_mut()) }, 0);
    }

    #[test]
    fn emits_full_words_in_big_endian_byte_order() {
        let _worker = install_openssl_worker();
        let limbs = [0x4433_2211, 0x8877_6655];
        let mut output = [0u8; 8];

        assert_eq!(unsafe { bn_bn2bin(&bignum(&limbs), output.as_mut_ptr()) }, 8);
        assert_eq!(output, [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn omits_high_zero_bytes_for_a_non_byte_aligned_magnitude() {
        let _worker = install_openssl_worker();
        let limbs = [0xdead_beef, 0x0000_0123];
        let mut output = [0xa5u8; 8];

        assert_eq!(unsafe { bn_bn2bin(&bignum(&limbs), output.as_mut_ptr()) }, 6);
        assert_eq!(&output[..6], &[0x01, 0x23, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&output[6..], &[0xa5, 0xa5], "the six-byte output bound is exact");
    }
}
