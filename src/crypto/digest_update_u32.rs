//! Feed one MBA-encoded big-endian word into Apple's proprietary digest.
//!
//! `digest_update_u32` — original: `FUN_0832bd54` @ 0x0832bd54 (84 bytes;
//! next separately entered function starts at 0x0832bda8). Six direct call
//! sites, all unconditional `bl`; no predicated forms or plain tail branches,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`.
//!
//! # Algorithm
//!
//! The wrapper extracts `value` most-significant byte first. It applies the
//! byte-wise MBA expression `byte * -99 - 20` (modulo 256), equivalently
//! `byte * 157 + 236`, then gives the resulting four bytes to
//! [`DIGEST_UPDATE`]. That worker's two-stage MBA expression is an identity,
//! so the digest receives those transformed big-endian bytes unchanged.
//!
//! Deliberate deviations: the stack-local byte array replaces four byte stores
//! at `sp + 0..3`; its byte order and transformed values are identical. The
//! unported update worker is reached through a volatile seam so LLVM retains
//! this call boundary until it is ported.

use super::digest_init::DigestCtx;

/// The proprietary digest's update worker: `(data, context, length)`.
pub type DigestUpdateFn = unsafe extern "C" fn(*const u8, *mut DigestCtx, u32) -> i32;

/// Target default: the stock digest-update worker @ 0x08338384.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_digest_update(
    data: *const u8,
    ctx: *mut DigestCtx,
    len: u32,
) -> i32 {
    let update: DigestUpdateFn = unsafe { core::mem::transmute(0x0833_8384usize) };
    unsafe { update(data, ctx, len) }
}

/// Host default: this wrapper cannot update a digest without its worker.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_digest_update(
    _data: *const u8,
    _ctx: *mut DigestCtx,
    _len: u32,
) -> i32 {
    panic!("digest_update_u32 requires digest_update worker 0x08338384")
}

/// Active digest-update worker. Host tests install a recording worker.
#[cfg(target_os = "none")]
pub static mut DIGEST_UPDATE: DigestUpdateFn = firmware_digest_update;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut DIGEST_UPDATE: DigestUpdateFn = missing_digest_update;

/// Loads the worker slot without letting LLVM fold the stock target into this
/// wrapper and eliminate the call boundary.
#[inline(always)]
unsafe fn digest_update() -> DigestUpdateFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DIGEST_UPDATE)) }
}

/// Encode and feed one 32-bit big-endian word to the proprietary digest.
///
/// # Safety
///
/// `ctx` must be accepted by the digest-update worker; the stock wrapper
/// forwards it without validating or dereferencing it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn digest_update_u32(value: u32, ctx: *mut DigestCtx) {
    let encoded = [
        ((value >> 24).wrapping_mul(157).wrapping_add(236)) as u8,
        ((value >> 16).wrapping_mul(157).wrapping_add(236)) as u8,
        ((value >> 8).wrapping_mul(157).wrapping_add(236)) as u8,
        (value.wrapping_mul(157).wrapping_add(236)) as u8,
    ];
    unsafe { digest_update()(encoded.as_ptr(), ctx, encoded.len() as u32) };
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use parking_lot::Mutex;
    static DIGEST_UPDATE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RECORDED_BYTES: [u8; 4] = [0; 4];
    static mut RECORDED_CTX: *mut DigestCtx = ptr::null_mut();
    static mut RECORDED_LEN: u32 = 0;

    unsafe extern "C" fn record_digest_update(
        data: *const u8,
        ctx: *mut DigestCtx,
        len: u32,
    ) -> i32 {
        unsafe {
            RECORDED_BYTES.copy_from_slice(core::slice::from_raw_parts(data, 4));
            RECORDED_CTX = ctx;
            RECORDED_LEN = len;
        }
        0x4d
    }

    struct DigestUpdateReset(DigestUpdateFn);

    impl Drop for DigestUpdateReset {
        fn drop(&mut self) {
            unsafe { DIGEST_UPDATE = self.0 };
        }
    }

    #[test]
    fn transforms_every_big_endian_byte_and_forwards_context() {
        let _guard = DIGEST_UPDATE_TEST_LOCK.lock();
        let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DIGEST_UPDATE)) };
        let _reset = DigestUpdateReset(saved);
        unsafe {
            DIGEST_UPDATE = record_digest_update;
        }

        let mut ctx = DigestCtx {
            reserved_00: [0; 16],
            length_lo: 0,
            length_hi: 0,
            state: [0; 5],
            reserved_5c: 0,
            state_len: 0,
            algorithm: 0,
        };
        for (value, expected) in [
            (0x0000_0000, [0xec, 0xec, 0xec, 0xec]),
            (0xffff_ffff, [0x4f, 0x4f, 0x4f, 0x4f]),
            (0x0123_4567, [0x89, 0x63, 0x3d, 0x17]),
            (0x80ff_7f00, [0x6c, 0x4f, 0xcf, 0xec]),
        ] {
            unsafe {
                RECORDED_BYTES = [0; 4];
                RECORDED_CTX = ptr::null_mut();
                RECORDED_LEN = 0;
                digest_update_u32(value, &mut ctx);
                assert_eq!(RECORDED_BYTES, expected, "value {value:#010x}");
                assert_eq!(RECORDED_CTX.cast_const(), core::ptr::addr_of!(ctx));
                assert_eq!(RECORDED_LEN, 4);
            }
        }
    }
}
