//! OpenSSL `BN_rand` — FUN_08040548 @ 0x08040548, 32 bytes.
//!
//! Raw A32 words establish the extent through the return at 0x08040564;
//! the separate range wrapper starts at 0x08040568. Two inbound plain BLs
//! occur at 0x08082420 and 0x080824bc; no predicated BLs. One outgoing
//! plain BL at 0x08040560 reaches 0x080e8b50, the random-bignum worker.
//!
//! Select cryptographic random mode 0, shift result/bits/top into the
//! worker's remaining register arguments, and pass bottom on the stack.
//! Return the worker's integer unchanged. Its raw body handles zero bits,
//! fills bytes via 0x080620f8, applies top/bottom constraints, converts via
//! BN_bin2bn @ 0x0803e2dc, then cleanses and frees the temporary bytes.
//! Deliberate deviation: the unported worker uses the existing volatile
//! dispatch-slot convention; the device default calls its verified address.

use super::bn_num_bits::BigNum;

pub type BnRandomFn = unsafe extern "C" fn(i32, *mut BigNum, i32, i32, i32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_random(mode: i32, result: *mut BigNum, bits: i32, top: i32, bottom: i32) -> i32 {
    let worker: BnRandomFn = unsafe { core::mem::transmute(0x080e_8b50usize) };
    unsafe { worker(mode, result, bits, top, bottom) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_random(_: i32, _: *mut BigNum, _: i32, _: i32, _: i32) -> i32 {
    panic!("bn_rand requires the random-bignum worker 0x080e8b50")
}

#[cfg(target_os = "none")]
pub static mut BN_RANDOM: BnRandomFn = firmware_bn_random;
#[cfg(not(target_os = "none"))]
pub static mut BN_RANDOM: BnRandomFn = missing_bn_random;

/// Generate a random bignum with the requested bit and parity constraints.
/// Original: 0x08040548, 32 bytes, two plain BL callers; no predicated BLs.
///
/// # Safety
/// `result` and the arguments must satisfy the stock random worker's
/// contract. On host, install `BN_RANDOM` before calling this function.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_rand(result: *mut BigNum, bits: i32, top: i32, bottom: i32) -> i32 {
    let worker = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_RANDOM)) };
    unsafe { worker(0, result, bits, top, bottom) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic byte-source model of the stock worker for one-word
    // results. Mode 1 models the weaker source, making mode selection
    // observable in the generated magnitude rather than a call recorder.
    unsafe extern "C" fn random_model(mode: i32, result: *mut BigNum, bits: i32, top: i32, bottom: i32) -> i32 {
        if bits == 0 {
            unsafe { (*result).top = 0; (*result).neg = 0; }
            return 1;
        }
        if bits < 0 || bits > 32 || unsafe { (*result).dmax } < 1 {
            return 0;
        }
        let mut value = if mode == 0 { 0x1234_5678u32 } else { 0x8765_4321u32 };
        if bits < 32 { value &= (1u32 << bits) - 1; }
        if top == 0 { value |= 1u32 << (bits - 1); }
        if top > 0 && bits >= 2 { value |= 3u32 << (bits - 2); }
        if bottom != 0 { value |= 1; }
        unsafe {
            (*result).d.cast_mut().write(value);
            (*result).top = if value == 0 { 0 } else { 1 };
            (*result).neg = 0;
        }
        1
    }

    #[test]
    fn constrained_magnitudes_zero_and_failure() {
        // Only this test touches this module's private-to-consumers slot.
        let old = unsafe { BN_RANDOM };
        unsafe { BN_RANDOM = random_model; }
        let mut limb = 0xdead_beefu32;
        let mut number = BigNum { d: &mut limb, top: 1, dmax: 1, neg: 1, flags: 0 };
        for (bits, top, bottom, expected) in [
            (8, -1, 0, 0x78), (8, 0, 0, 0xf8),
            (8, 1, 1, 0xf9), (9, 1, 0, 0x1f8),
            (32, -1, 1, 0x1234_5679), (32, 1, 0, 0xd234_5678),
            (1, 0, 1, 1),
        ] {
            assert_eq!(unsafe { bn_rand(&mut number, bits, top, bottom) }, 1);
            assert_eq!(limb, expected);
            assert_eq!((number.top, number.neg), (1, 0));
        }
        assert_eq!(unsafe { bn_rand(&mut number, 0, -1, 1) }, 1);
        assert_eq!((number.top, number.neg), (0, 0));
        number.dmax = 0;
        let before = limb;
        assert_eq!(unsafe { bn_rand(&mut number, 8, 0, 1) }, 0);
        assert_eq!(limb, before);
        assert_eq!(number.top, 0);
        unsafe { BN_RANDOM = old; }
    }
}
