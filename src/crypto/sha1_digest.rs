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
//! The three SHA-1 primitives are not yet ported. Target builds therefore
//! reach their stock entries through volatile seams, retaining the original
//! call boundaries; host tests replace those seams to observe the ABI.

/// The exact 352-byte stack context used by the retail wrapper.
#[repr(C, align(4))]
pub struct Sha1Context {
    words: [u32; 88],
}

/// Stock `SHA1_Init(context)` entry point.
pub type Sha1InitFn = unsafe extern "C" fn(*mut Sha1Context);
/// Stock `SHA1_Update(context, input, input_len)` entry point.
pub type Sha1UpdateFn = unsafe extern "C" fn(*mut Sha1Context, *const u8, u32);
/// Stock `SHA1_Final(context, output)` entry point.
pub type Sha1FinalFn = unsafe extern "C" fn(*mut Sha1Context, *mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_sha1_init(context: *mut Sha1Context) {
    let init: Sha1InitFn = unsafe { core::mem::transmute(0x080e_c1bcusize) };
    unsafe { init(context) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sha1_init(_context: *mut Sha1Context) {
    panic!("sha1_digest requires SHA1_Init worker 0x080ec1bc")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_sha1_update(
    context: *mut Sha1Context,
    input: *const u8,
    input_len: u32,
) {
    let update: Sha1UpdateFn = unsafe { core::mem::transmute(0x080f_4fd8usize) };
    unsafe { update(context, input, input_len) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sha1_update(
    _context: *mut Sha1Context,
    _input: *const u8,
    _input_len: u32,
) {
    panic!("sha1_digest requires SHA1_Update worker 0x080f4fd8")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_sha1_final(context: *mut Sha1Context, output: *mut u8) {
    let final_: Sha1FinalFn = unsafe { core::mem::transmute(0x080e_fbc8usize) };
    unsafe { final_(context, output) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sha1_final(_context: *mut Sha1Context, _output: *mut u8) {
    panic!("sha1_digest requires SHA1_Final worker 0x080efbc8")
}

/// Active `SHA1_Init` seam. Host tests replace it with an ABI recorder.
#[cfg(target_os = "none")]
pub static mut SHA1_INIT: Sha1InitFn = firmware_sha1_init;
#[cfg(not(target_os = "none"))]
pub static mut SHA1_INIT: Sha1InitFn = missing_sha1_init;

/// Active `SHA1_Update` seam. Host tests replace it with an ABI recorder.
#[cfg(target_os = "none")]
pub static mut SHA1_UPDATE: Sha1UpdateFn = firmware_sha1_update;
#[cfg(not(target_os = "none"))]
pub static mut SHA1_UPDATE: Sha1UpdateFn = missing_sha1_update;

/// Active `SHA1_Final` seam. Host tests replace it with an ABI recorder.
#[cfg(target_os = "none")]
pub static mut SHA1_FINAL: Sha1FinalFn = firmware_sha1_final;
#[cfg(not(target_os = "none"))]
pub static mut SHA1_FINAL: Sha1FinalFn = missing_sha1_final;

#[inline(always)]
unsafe fn sha1_init() -> Sha1InitFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SHA1_INIT)) }
}

#[inline(always)]
unsafe fn sha1_update() -> Sha1UpdateFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SHA1_UPDATE)) }
}

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
        sha1_init()(context);
        sha1_update()(context, input, input_len);
        sha1_final()(context, output);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static SHA1_DIGEST_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_SEQUENCE: [u8; 3] = [0; 3];
    static mut CALL_COUNT: usize = 0;
    static mut INIT_CONTEXT: *mut Sha1Context = ptr::null_mut();
    static mut UPDATE_CONTEXT: *mut Sha1Context = ptr::null_mut();
    static mut FINAL_CONTEXT: *mut Sha1Context = ptr::null_mut();
    static mut UPDATE_INPUT: *const u8 = ptr::null();
    static mut UPDATE_LEN: u32 = 0;
    static mut FINAL_OUTPUT: *mut u8 = ptr::null_mut();

    unsafe fn record_call(kind: u8) {
        unsafe {
            CALL_SEQUENCE[CALL_COUNT] = kind;
            CALL_COUNT += 1;
        }
    }

    unsafe extern "C" fn record_sha1_init(context: *mut Sha1Context) {
        unsafe {
            record_call(1);
            INIT_CONTEXT = context;
            (*context).words[0] = 0x0123_4567;
        }
    }

    unsafe extern "C" fn record_sha1_update(
        context: *mut Sha1Context,
        input: *const u8,
        input_len: u32,
    ) {
        unsafe {
            record_call(2);
            UPDATE_CONTEXT = context;
            UPDATE_INPUT = input;
            UPDATE_LEN = input_len;
            assert_eq!((*context).words[0], 0x0123_4567);
        }
    }

    unsafe extern "C" fn record_sha1_final(context: *mut Sha1Context, output: *mut u8) {
        unsafe {
            record_call(3);
            FINAL_CONTEXT = context;
            FINAL_OUTPUT = output;
        }
    }

    struct Sha1SeamReset(Sha1InitFn, Sha1UpdateFn, Sha1FinalFn);

    impl Drop for Sha1SeamReset {
        fn drop(&mut self) {
            unsafe {
                SHA1_INIT = self.0;
                SHA1_UPDATE = self.1;
                SHA1_FINAL = self.2;
            }
        }
    }

    #[test]
    fn forwards_nonempty_and_empty_inputs_through_one_initialized_context() {
        let _guard = SHA1_DIGEST_TEST_LOCK.lock();
        let saved = unsafe {
            (
                core::ptr::read_volatile(core::ptr::addr_of!(SHA1_INIT)),
                core::ptr::read_volatile(core::ptr::addr_of!(SHA1_UPDATE)),
                core::ptr::read_volatile(core::ptr::addr_of!(SHA1_FINAL)),
            )
        };
        let _reset = Sha1SeamReset(saved.0, saved.1, saved.2);
        unsafe {
            SHA1_INIT = record_sha1_init;
            SHA1_UPDATE = record_sha1_update;
            SHA1_FINAL = record_sha1_final;
        }

        let input = [0x00, 0x80, 0xff];
        let mut output = [0u8; 20];
        for (input_ptr, input_len) in [(input.as_ptr(), 3), (ptr::null(), 0)] {
            unsafe {
                CALL_SEQUENCE = [0; 3];
                CALL_COUNT = 0;
                INIT_CONTEXT = ptr::null_mut();
                UPDATE_CONTEXT = ptr::null_mut();
                FINAL_CONTEXT = ptr::null_mut();
                UPDATE_INPUT = ptr::null();
                UPDATE_LEN = 0;
                FINAL_OUTPUT = ptr::null_mut();
                sha1_digest(input_ptr, input_len, output.as_mut_ptr());
                assert_eq!(CALL_SEQUENCE, [1, 2, 3]);
                assert_eq!(CALL_COUNT, 3);
                assert_eq!(UPDATE_INPUT, input_ptr);
                assert_eq!(UPDATE_LEN, input_len);
                assert_eq!(FINAL_OUTPUT, output.as_mut_ptr());
                assert_eq!(INIT_CONTEXT, UPDATE_CONTEXT);
                assert_eq!(UPDATE_CONTEXT, FINAL_CONTEXT);
                assert_eq!((INIT_CONTEXT as usize) & 3, 0);
            }
        }
    }
}
