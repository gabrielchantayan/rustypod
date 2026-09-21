//! OpenSSL's `i2s_ASN1_INTEGER` text-conversion helper.
//!
//! Port: `i2s_asn1_integer` — `FUN_082d39bc` @ 0x082d39bc (92 bytes,
//! 0x082d39bc..0x082d3a18; the next separately linked function starts at
//! 0x082d3a18). Full-image A32 decoding finds three inbound plain `bl` calls
//! (0x0806eb68, 0x0807d1c4, 0x080f5114) and no predicated inbound `bl` calls.
//! The body has four outbound plain `bl` instructions: `ASN1_INTEGER_to_BN`,
//! `BN_bn2dec`, `diag_ring_record`, and `releasable_buffer_release`.
//!
//! # Algorithm
//!
//! Convert the ASN.1 integer to a temporary BIGNUM, render that BIGNUM in
//! decimal, log `(0x22, 0x78, 0x41, 0, 0)` if either allocation/conversion
//! fails, release the temporary BIGNUM, and return the decimal buffer or NULL.
//! The two conversion workers are still retailOS code, so target builds call
//! their verified stock addresses while host tests install volatile workers.
//! That dispatch is the only deliberate deviation.

use core::ptr;

use crate::crypto::bn_num_bits::BigNum;
use crate::heap::releasable_buffer::releasable_buffer_release;
use crate::kernel::diag_ring_record::diag_ring_record;

pub type Asn1IntegerToBnFn = unsafe extern "C" fn(*const u32, *mut BigNum) -> *mut BigNum;
pub type BnToDecimalFn = unsafe extern "C" fn(*const BigNum) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_asn1_integer_to_bn(value: *const u32, bn: *mut BigNum) -> *mut BigNum {
    let worker: Asn1IntegerToBnFn = unsafe { core::mem::transmute(0x0803_a0d0usize) };
    unsafe { worker(value, bn) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_asn1_integer_to_bn(_value: *const u32, _bn: *mut BigNum) -> *mut BigNum {
    panic!("i2s_asn1_integer requires ASN1_INTEGER_to_BN 0x0803a0d0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_bn_to_decimal(bn: *const BigNum) -> *mut u8 {
    let worker: BnToDecimalFn = unsafe { core::mem::transmute(0x0803_e438usize) };
    unsafe { worker(bn) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bn_to_decimal(_bn: *const BigNum) -> *mut u8 {
    panic!("i2s_asn1_integer requires BN_bn2dec 0x0803e438")
}

#[cfg(target_os = "none")]
pub static mut ASN1_INTEGER_TO_BN: Asn1IntegerToBnFn = firmware_asn1_integer_to_bn;
#[cfg(not(target_os = "none"))]
pub static mut ASN1_INTEGER_TO_BN: Asn1IntegerToBnFn = missing_asn1_integer_to_bn;
#[cfg(target_os = "none")]
pub static mut BN_TO_DECIMAL: BnToDecimalFn = firmware_bn_to_decimal;
#[cfg(not(target_os = "none"))]
pub static mut BN_TO_DECIMAL: BnToDecimalFn = missing_bn_to_decimal;

#[inline(always)]
unsafe fn asn1_integer_to_bn() -> Asn1IntegerToBnFn {
    unsafe { ptr::read_volatile(ptr::addr_of!(ASN1_INTEGER_TO_BN)) }
}

#[inline(always)]
unsafe fn bn_to_decimal() -> BnToDecimalFn {
    unsafe { ptr::read_volatile(ptr::addr_of!(BN_TO_DECIMAL)) }
}

/// `i2s_ASN1_INTEGER` — original: `FUN_082d39bc` @ 0x082d39bc (92 bytes;
/// three inbound unconditional `bl` call sites, binary-verified).
///
/// Converts `value` through `ASN1_INTEGER_to_BN(value, NULL)`, returns its
/// `BN_bn2dec` string, and always releases the temporary BIGNUM. Either NULL
/// result records the retail diagnostic event before returning NULL.
///
/// # Safety
///
/// `value` and all memory reached by the installed conversion workers must be
/// valid. On host, [`ASN1_INTEGER_TO_BN`] and [`BN_TO_DECIMAL`] must be set.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn i2s_asn1_integer(_method: *const u32, value: *const u32) -> *mut u8 {
    let bn = unsafe { asn1_integer_to_bn()(value, ptr::null_mut()) };
    let decimal = if bn.is_null() {
        unsafe { diag_ring_record(0x22, 0x78, 0x41, 0, 0) };
        ptr::null_mut()
    } else {
        let decimal = unsafe { bn_to_decimal()(bn) };
        if decimal.is_null() {
            unsafe { diag_ring_record(0x22, 0x78, 0x41, 0, 0) };
        }
        decimal
    };
    unsafe { releasable_buffer_release(bn.cast()) };
    decimal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    // The release helper consumes the target's five 32-bit words. Do not use
    // `BigNum` here: its host pointer field is eight bytes wide.
    static mut BN_WORDS: [u32; 5] = [0, 0, 0, 0, 1];
    static mut DECIMAL: [u8; 3] = *b"42\0";
    static mut SEEN_VALUE: *const u32 = core::ptr::null();
    static mut SEEN_OUTPUT: *mut BigNum = 1 as *mut BigNum;
    static mut RELEASED: *mut u8 = 1 as *mut u8;

    unsafe extern "C" fn converts(value: *const u32, output: *mut BigNum) -> *mut BigNum {
        unsafe {
            SEEN_VALUE = value;
            SEEN_OUTPUT = output;
            BN_WORDS[4] = 1;
            core::ptr::addr_of_mut!(BN_WORDS).cast()
        }
    }
    unsafe extern "C" fn conversion_fails(_value: *const u32, _output: *mut BigNum) -> *mut BigNum { core::ptr::null_mut() }
    unsafe extern "C" fn renders(_bn: *const BigNum) -> *mut u8 { unsafe { core::ptr::addr_of_mut!(DECIMAL).cast() } }
    unsafe extern "C" fn render_fails(_bn: *const BigNum) -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn record_release(block: *mut u8) { unsafe { RELEASED = block } }

    struct Hooks { old_convert: Asn1IntegerToBnFn, old_render: BnToDecimalFn, old_free: TracedFreeHooks }
    impl Drop for Hooks {
        fn drop(&mut self) {
            unsafe { ASN1_INTEGER_TO_BN = self.old_convert; BN_TO_DECIMAL = self.old_render; TRACED_FREE_HOOKS = self.old_free; }
        }
    }
    unsafe fn install(convert: Asn1IntegerToBnFn, render: BnToDecimalFn) -> Hooks {
        unsafe {
            let hooks = Hooks { old_convert: ptr::read_volatile(ptr::addr_of!(ASN1_INTEGER_TO_BN)), old_render: ptr::read_volatile(ptr::addr_of!(BN_TO_DECIMAL)), old_free: ptr::read_volatile(ptr::addr_of!(TRACED_FREE_HOOKS)) };
            ASN1_INTEGER_TO_BN = convert;
            BN_TO_DECIMAL = render;
            TRACED_FREE_HOOKS = TracedFreeHooks { free: record_release, trace: None };
            RELEASED = 1 as *mut u8;
            hooks
        }
    }

    #[test]
    fn converts_renders_and_releases_the_temporary_bignum() {
        let _serial = TEST_LOCK.lock();
        let _free = TRACED_FREE_TEST_LOCK.lock();
        let _hooks = unsafe { install(converts, renders) };
        let value = 0x1234_u32;
        let result = unsafe { i2s_asn1_integer(ptr::null(), &value) };
        assert_eq!(result, unsafe { core::ptr::addr_of_mut!(DECIMAL).cast() });
        assert_eq!(unsafe { SEEN_VALUE }, &value);
        assert!(unsafe { SEEN_OUTPUT }.is_null());
        assert_eq!(unsafe { RELEASED }, unsafe { core::ptr::addr_of_mut!(BN_WORDS).cast() });
    }

    #[test]
    fn conversion_failure_returns_null_without_releasing() {
        let _serial = TEST_LOCK.lock();
        let _free = TRACED_FREE_TEST_LOCK.lock();
        let _hooks = unsafe { install(conversion_fails, renders) };
        assert!(unsafe { i2s_asn1_integer(ptr::null(), ptr::null()) }.is_null());
        assert_eq!(unsafe { RELEASED }, 1 as *mut u8);
    }

    #[test]
    fn decimal_failure_releases_the_converted_bignum() {
        let _serial = TEST_LOCK.lock();
        let _free = TRACED_FREE_TEST_LOCK.lock();
        let _hooks = unsafe { install(converts, render_fails) };
        assert!(unsafe { i2s_asn1_integer(ptr::null(), ptr::null()) }.is_null());
        assert_eq!(unsafe { RELEASED }, unsafe { core::ptr::addr_of_mut!(BN_WORDS).cast() });
    }
}
