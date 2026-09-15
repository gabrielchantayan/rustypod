//! OpenSSL BIO-based base64 decoder.
//!
//! Port: `base64_decode` — `FUN_082728cc` @ `0x082728cc` (**216 bytes**,
//! `0x082728cc..0x082729a4`; the next separately linked function opens at
//! `0x082729a4`). Raw decoding found **5 inbound call sites**, all plain
//! unconditional `bl`, and no predicated `bl`: `0x082729d4`, `0x08272b18`,
//! `0x08272c00`, `0x082734f0`, and `0x08273584`.
//!
//! # Algorithm
//!
//! Creates the two verified BIO method factories at `0x0803d358` and
//! `0x0803d8a8`, chains the resulting BIOs, writes the encoded input through
//! the chain, enables control code 11 on its head, and obtains the decoded
//! memory BIO buffer with control code 3. If `decoded_len + 1` fits the
//! caller's capacity, it copies the bytes and places two trailing NULs. It
//! always stores `decoded_len - 1` and destroys the chain after both BIOs
//! were created.
//!
//! # Deliberate deviations
//!
//! The method factories, `BIO_push`, `BIO_write`, and `BIO_free_all` are not
//! ported. Firmware builds enter their verified retailOS addresses; host tests
//! model those ABI boundaries. `param_1` is retained in the ABI but unused by
//! the original.
#[cfg(not(target_os = "none"))]
use core::ffi::c_void;

use core::ptr;
#[cfg(target_os = "none")]
use crate::crypto::bio_ctrl::bio_ctrl;
use crate::crypto::bio_ctrl::{Bio, BioMethod};
#[cfg(target_os = "none")]
use crate::crypto::bio_new::bio_new;
#[cfg(target_os = "none")]
use crate::libc::rt_memcpy::__rt_memcpy;

type BioMethodFactory = unsafe extern "C" fn() -> *mut BioMethod;
type BioPushFn = unsafe extern "C" fn(*mut Bio, *mut Bio) -> *mut Bio;
type BioWriteFn = unsafe extern "C" fn(*mut Bio, *const u8, i32) -> i32;
type BioFreeAllFn = unsafe extern "C" fn(*mut Bio);

const BIO_FILTER_METHOD_ADDRESS: usize = 0x0803_d358;
const BIO_MEMORY_METHOD_ADDRESS: usize = 0x0803_d8a8;
const BIO_PUSH_ADDRESS: usize = 0x0803_d69c;
const BIO_WRITE_ADDRESS: usize = 0x0803_da74;
const BIO_FREE_ALL_ADDRESS: usize = 0x0803_d454;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct Base64DecodeOps {
    pub filter_method: BioMethodFactory,
    pub memory_method: BioMethodFactory,
    pub new: unsafe extern "C" fn(*mut BioMethod) -> *mut Bio,
    pub push: BioPushFn,
    pub write: BioWriteFn,
    pub ctrl: unsafe extern "C" fn(*mut Bio, i32, i32, *mut c_void) -> i32,
    pub free_all: BioFreeAllFn,
    pub copy: unsafe extern "C" fn(*mut u8, *const u8, usize),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_factory() -> *mut BioMethod { ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_new(_method: *mut BioMethod) -> *mut Bio { ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_push(_bio: *mut Bio, _append: *mut Bio) -> *mut Bio { ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_write(_bio: *mut Bio, _input: *const u8, _len: i32) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ctrl(_bio: *mut Bio, _cmd: i32, _larg: i32, _parg: *mut c_void) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_free_all(_bio: *mut Bio) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_copy(_dst: *mut u8, _src: *const u8, _len: usize) {}

#[cfg(not(target_os = "none"))]
pub static mut BASE64_DECODE_OPS: Base64DecodeOps = Base64DecodeOps {
    filter_method: missing_factory,
    memory_method: missing_factory,
    new: missing_new,
    push: missing_push,
    write: missing_write,
    ctrl: missing_ctrl,
    free_all: missing_free_all,
    copy: missing_copy,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn decode_ops() -> Base64DecodeOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(BASE64_DECODE_OPS)) }
}
#[inline(always)]
unsafe fn new_bio(method: *mut BioMethod) -> *mut Bio {
    #[cfg(target_os = "none")]
    { unsafe { bio_new(method) } }
    #[cfg(not(target_os = "none"))]
    { unsafe { (decode_ops().new)(method) } }
}


/// base64_decode — original: `FUN_082728cc` @ 0x082728cc (216 bytes; 5
/// direct unconditional `bl` call sites, no predicated calls).
///
/// # Safety
/// `input` must be valid for `input_len` bytes; `output_capacity` and, when
/// sufficient, `output` must be valid writable pointers. The ignored first
/// argument is retained for ABI parity.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn base64_decode(
    _unused: u32,
    input: *const u8,
    input_len: i32,
    output: *mut u8,
    output_capacity: *mut u32,
) -> i32 {
    #[cfg(target_os = "none")]
    let filter = unsafe { core::mem::transmute::<usize, BioMethodFactory>(BIO_FILTER_METHOD_ADDRESS) };
    #[cfg(not(target_os = "none"))]
    let filter = unsafe { decode_ops().filter_method };
    let head = unsafe { new_bio(filter()) };
    if head.is_null() { return -1; }

    #[cfg(target_os = "none")]
    let memory = unsafe { core::mem::transmute::<usize, BioMethodFactory>(BIO_MEMORY_METHOD_ADDRESS) };
    #[cfg(not(target_os = "none"))]
    let memory = unsafe { decode_ops().memory_method };
    let tail = unsafe { new_bio(memory()) };
    if tail.is_null() {
        #[cfg(target_os = "none")]
        unsafe { core::mem::transmute::<usize, BioFreeAllFn>(BIO_FREE_ALL_ADDRESS)(head) };
        #[cfg(not(target_os = "none"))]
        unsafe { (decode_ops().free_all)(head) };
        return -1;
    }

    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, BioPushFn>(BIO_PUSH_ADDRESS)(head, tail) };
    #[cfg(not(target_os = "none"))]
    unsafe { (decode_ops().push)(head, tail) };
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, BioWriteFn>(BIO_WRITE_ADDRESS)(head, input, input_len) };
    #[cfg(not(target_os = "none"))]
    unsafe { (decode_ops().write)(head, input, input_len) };
    #[cfg(target_os = "none")]
    unsafe { bio_ctrl(head, 11, 0, ptr::null_mut()) };
    #[cfg(not(target_os = "none"))]
    unsafe { (decode_ops().ctrl)(head, 11, 0, ptr::null_mut()) };

    let mut decoded: *const u8 = ptr::null();
    #[cfg(target_os = "none")]
    let decoded_len = unsafe { bio_ctrl(tail, 3, 0, ptr::addr_of_mut!(decoded).cast()) } as u32;
    #[cfg(not(target_os = "none"))]
    let decoded_len = unsafe { (decode_ops().ctrl)(tail, 3, 0, ptr::addr_of_mut!(decoded).cast()) } as u32;
    if unsafe { *output_capacity } >= decoded_len.wrapping_add(1) {
        #[cfg(target_os = "none")]
        unsafe { __rt_memcpy(output, decoded, decoded_len as usize); }
        #[cfg(not(target_os = "none"))]
        unsafe { (decode_ops().copy)(output, decoded, decoded_len as usize); }
        unsafe { output.add(decoded_len as usize).write(0); }
        unsafe { output.add(decoded_len.wrapping_sub(1) as usize).write(0); }
    }
    unsafe { output_capacity.write(decoded_len.wrapping_sub(1)); }
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, BioFreeAllFn>(BIO_FREE_ALL_ADDRESS)(head) };
    #[cfg(not(target_os = "none"))]
    unsafe { (decode_ops().free_all)(head) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DECODED: [u8; 4] = *b"abc!";
    static mut CALLS: [u32; 5] = [0; 5];

    unsafe extern "C" fn filter_method() -> *mut BioMethod { 1usize as *mut BioMethod }
    unsafe extern "C" fn memory_method() -> *mut BioMethod { 2usize as *mut BioMethod }
    unsafe extern "C" fn new(_method: *mut BioMethod) -> *mut Bio {
        unsafe { CALLS[0] += 1; }
        unsafe { (0x100 + CALLS[0] as usize) as *mut Bio }
    }
    unsafe extern "C" fn push(_head: *mut Bio, _tail: *mut Bio) -> *mut Bio {
        unsafe { CALLS[1] += 1; }
        ptr::null_mut()
    }
    unsafe extern "C" fn write(_bio: *mut Bio, _input: *const u8, _len: i32) -> i32 {
        unsafe { CALLS[2] += 1; }
        0
    }
    unsafe extern "C" fn ctrl(_bio: *mut Bio, cmd: i32, _larg: i32, parg: *mut c_void) -> i32 {
        unsafe { CALLS[3] += 1; }
        if cmd == 3 {
            unsafe { parg.cast::<*const u8>().write(ptr::addr_of!(DECODED).cast()); }
            4
        } else {
            assert_eq!(cmd, 11);
            0
        }
    }
    unsafe extern "C" fn free_all(_bio: *mut Bio) { unsafe { CALLS[4] += 1; } }
    unsafe extern "C" fn copy(dst: *mut u8, src: *const u8, len: usize) {
        unsafe { ptr::copy_nonoverlapping(src, dst, len); }
    }

    fn install() -> Base64DecodeOps {
        unsafe {
            let old = ptr::read_volatile(ptr::addr_of!(BASE64_DECODE_OPS));
            BASE64_DECODE_OPS = Base64DecodeOps {
                filter_method, memory_method, new, push, write, ctrl, free_all, copy,
            };
            CALLS = [0; 5];
            old
        }
    }

    #[test]
    fn copies_decoded_bytes_and_two_nuls_when_capacity_includes_terminator() {
        let _lock = TEST_LOCK.lock();
        let old = install();
        let mut output = [0xff; 6];
        let mut capacity = 5;
        assert_eq!(unsafe { base64_decode(0, b"YWJj".as_ptr(), 4, output.as_mut_ptr(), &mut capacity) }, 0);
        assert_eq!(output, [b'a', b'b', b'c', 0, 0, 0xff]);
        assert_eq!(capacity, 3);
        assert_eq!(unsafe { CALLS }, [2, 1, 1, 2, 1]);
        unsafe { BASE64_DECODE_OPS = old; }
    }

    #[test]
    fn short_capacity_skips_copy_but_still_reports_decoded_length_minus_one() {
        let _lock = TEST_LOCK.lock();
        let old = install();
        let mut output = [0xaa; 4];
        let mut capacity = 4;
        assert_eq!(unsafe { base64_decode(0, b"YWJj".as_ptr(), 4, output.as_mut_ptr(), &mut capacity) }, 0);
        assert_eq!(output, [0xaa; 4]);
        assert_eq!(capacity, 3);
        assert_eq!(unsafe { CALLS }, [2, 1, 1, 2, 1]);
        unsafe { BASE64_DECODE_OPS = old; }
    }
}
