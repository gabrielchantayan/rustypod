//! RetailOS SHA-1 one-shot wrapper.
//!
//! `sha1_digest` — original: `FUN_083691a0` @ 0x083691a0 (64 instruction
//! bytes; `0x083691a0..0x083691e0`, followed by a separately linked function).
//! Decoding every ARM B/BL word in `osos.dec` finds five direct inbound calls,
//! all unconditional `bl` instructions at `0x0803c66c`, `0x0803c6f8`,
//! `0x0807ea48`, `0x080e37a4`, and `0x080e37e8`; there are no predicated
//! calls or tail branches.
//!
//! # Algorithm
//!
//! Allocates the 352-byte SHA-1 context on the stack, initializes it through
//! `SHA1_Init` @ 0x080ec1bc, feeds `(input, input_len)` through `SHA1_Update`
//! @ 0x080f4fd8, then writes the 20-byte digest through `SHA1_Final` @
//! 0x080efbc8. It has no NULL or length guard: all three arguments are
//! forwarded exactly as supplied.
//!
//! # Deliberate deviation
//!
//! `SHA1_Init` and `SHA1_Update` are ported locally. `SHA1_Final` and the
//! update block transform remain explicit stock-entry seams.

use super::sha1_update::{sha1_update, Sha1Context};
use super::sha1_init::sha1_init;

/// Stock `SHA1_Final(context, output)` entry point.
pub type Sha1FinalFn = unsafe extern "C" fn(*mut Sha1Context, *mut u8);


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_sha1_final(context: *mut Sha1Context, output: *mut u8) {
    let final_: Sha1FinalFn = unsafe { core::mem::transmute(0x080e_fbc8usize) };
    unsafe { final_(context, output) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sha1_final(_context: *mut Sha1Context, _output: *mut u8) {
    panic!("sha1_digest requires SHA1_Final worker 0x080efbc8")
}


/// Active `SHA1_Final` seam. Host tests replace it with an ABI recorder.
#[cfg(target_os = "none")]
pub static mut SHA1_FINAL: Sha1FinalFn = firmware_sha1_final;
#[cfg(not(target_os = "none"))]
pub static mut SHA1_FINAL: Sha1FinalFn = missing_sha1_final;


#[inline(always)]
unsafe fn sha1_final() -> Sha1FinalFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SHA1_FINAL)) }
}

/// `SHA1(input, input_len, output)` — original: `FUN_083691a0` @ 0x083691a0
/// (64 bytes; five unconditional `bl` call sites, binary-verified).
///
/// Initializes a stack SHA-1 context, updates it from `input`, and finalizes
/// its digest into `output` through the stock SHA-1 primitive entries.
///
/// # Safety
///
/// `input` and `input_len` must be valid for the stock `SHA1_Update` worker;
/// `output` must be accepted by its `SHA1_Final` worker. The wrapper forwards
/// every argument without validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sha1_digest(input: *const u8, input_len: u32, output: *mut u8) {
    let mut context = core::mem::MaybeUninit::<Sha1Context>::uninit();
    let context = context.as_mut_ptr();
    unsafe {
        sha1_init(context);
        sha1_update(context, input, input_len);
        sha1_final()(context, output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static SHA1_DIGEST_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED: [u32; 88] = [0; 88];

    unsafe extern "C" fn capture_context(context: *mut Sha1Context, _output: *mut u8) {
        unsafe { OBSERVED = (*context).words };
    }

    struct FinalReset(Sha1FinalFn);

    impl Drop for FinalReset {
        fn drop(&mut self) {
            unsafe { SHA1_FINAL = self.0 };
        }
    }

    #[test]
    fn initializes_and_counts_empty_and_partial_block_inputs() {
        let _guard = SHA1_DIGEST_TEST_LOCK.lock();
        let _reset = FinalReset(unsafe { SHA1_FINAL });
        unsafe { SHA1_FINAL = capture_context };
        let input = [0x00, 0x80, 0xff];
        let mut output = [0u8; 20];
        for len in [0, 3] {
            unsafe { sha1_digest(input.as_ptr(), len, output.as_mut_ptr()) };
            let words = unsafe { OBSERVED };
            assert_eq!(&words[..5], &[0x67452301, 0xefcdab89, 0x98badcfe,
                0x10325476, 0xc3d2e1f0]);
            assert_eq!(words[5], if len == 0 { 0 } else { 0x0080ff });
            assert_eq!(&words[6..85], &[0; 79]);
            assert_eq!(&words[85..], &[len, 0, len * 8]);
        }
    }
}
