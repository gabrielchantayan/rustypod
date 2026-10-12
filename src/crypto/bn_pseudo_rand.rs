//! OpenSSL `BN_pseudo_rand` — FUN_08040518 @ 0x08040518, 32 bytes.
//!
//! Raw A32 extent ends at 0x08040538, the independent range wrapper.
//! Two inbound plain BLs at 0x08082418 and 0x080824b4; zero predicated
//! BLs. One outgoing plain BL at 0x08040530 calls 0x080e8b50.
//! Save bottom as the fifth stack argument, shift result/bits/top into
//! r1/r2/r3, select pseudo-random mode 1, and return the worker's integer
//! unchanged. Callers use top=-1 and bottom=0 and check success.
//! Deliberate deviation: reuse bn_rand's volatile BN_RANDOM dispatch slot
//! for the unported stock worker; no extra allocation or validation.

use super::bn_num_bits::BigNum;
use super::bn_rand::BN_RANDOM;

/// Generate a pseudo-random bignum with bit and parity constraints.
/// Original: 0x08040518, 32 bytes; two plain BL callers, no predicated BLs.
///
/// # Safety
/// `result` and the constraints must satisfy the stock worker's contract.
/// On host, install `BN_RANDOM` before calling this function.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_pseudo_rand(result: *mut BigNum, bits: i32, top: i32, bottom: i32) -> i32 {
    let worker = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BN_RANDOM)) };
    unsafe { worker(1, result, bits, top, bottom) }
}
