//! EVP cipher-update direction dispatch.
//!
//! `FUN_08049f88` @ 0x08049f88: 48 bytes, ending at the independent
//! push at 0x08049fb8. Raw A32 decoding verifies two outgoing plain BLs,
//! zero predicated BLs; two incoming plain BLs, zero predicated BLs.
//! Context word 2 is the encrypt flag: any nonzero value selects the
//! encrypt-update worker (0x0804aa88), zero selects decrypt-update
//! (0x0804a43c). All five arguments and the worker's i32 result survive.
//!
//! Deliberate deviations: volatile worker slots preserve the unported stock
//! call boundaries and permit host fixtures. Context uses target u32 words,
//! not host-sized pointer fields. No validation or cipher algorithm is added.
//! ARM match review: LLVM emits 12 instructions, selecting a worker slot with
//! MOVEQ and tail-dispatching through BX instead of two BL/return paths.
//! The fifth argument stays in its incoming stack slot and r0 is returned
//! directly by the worker. The slot's stock wrapper then calls the raw address.

/// Stock EVP update ABI; context remains opaque except for direction word 2.
pub type CipherUpdateFn = unsafe extern "C" fn(
    *mut u32, *mut u8, *mut i32, *const u8, i32,
) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_encrypt_update(
    ctx: *mut u32, output: *mut u8, output_len: *mut i32, input: *const u8, len: i32,
) -> i32 {
    let worker: CipherUpdateFn = unsafe { core::mem::transmute(0x0804_aa88usize) };
    unsafe { worker(ctx, output, output_len, input, len) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_decrypt_update(
    ctx: *mut u32, output: *mut u8, output_len: *mut i32, input: *const u8, len: i32,
) -> i32 {
    let worker: CipherUpdateFn = unsafe { core::mem::transmute(0x0804_a43cusize) };
    unsafe { worker(ctx, output, output_len, input, len) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(
    _: *mut u32, _: *mut u8, _: *mut i32, _: *const u8, _: i32,
) -> i32 {
    panic!("evp_cipher_update requires stock EVP encrypt/decrypt update workers")
}

#[cfg(target_os = "none")]
pub static mut ENCRYPT_UPDATE: CipherUpdateFn = firmware_encrypt_update;
#[cfg(target_os = "none")]
pub static mut DECRYPT_UPDATE: CipherUpdateFn = firmware_decrypt_update;
#[cfg(not(target_os = "none"))]
pub static mut ENCRYPT_UPDATE: CipherUpdateFn = missing_update;
#[cfg(not(target_os = "none"))]
pub static mut DECRYPT_UPDATE: CipherUpdateFn = missing_update;

/// Update an EVP cipher using its current direction.
///
/// # Safety
/// `ctx` must contain at least three aligned u32 words and be valid for the
/// selected worker. Buffers and lengths must satisfy that worker's contract.
/// Worker slots must not be changed concurrently with calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn evp_cipher_update(
    ctx: *mut u32, output: *mut u8, output_len: *mut i32, input: *const u8, len: i32,
) -> i32 {
    let slot = if unsafe { ctx.add(2).read() } != 0 {
        core::ptr::addr_of!(ENCRYPT_UPDATE)
    } else {
        core::ptr::addr_of!(DECRYPT_UPDATE)
    };
    let worker = unsafe { slot.read_volatile() };
    unsafe { worker(ctx, output, output_len, input, len) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn encrypt(
        _: *mut u32, _: *mut u8, out_len: *mut i32, _: *const u8, _: i32,
    ) -> i32 {
        unsafe { out_len.write(16) };
        -7
    }
    unsafe extern "C" fn decrypt(
        _: *mut u32, _: *mut u8, out_len: *mut i32, _: *const u8, _: i32,
    ) -> i32 {
        unsafe { out_len.write(0) };
        1
    }
    struct Reset(CipherUpdateFn, CipherUpdateFn);
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { ENCRYPT_UPDATE = self.0; DECRYPT_UPDATE = self.1; }
        }
    }

    #[test]
    fn direction_is_zero_vs_nonzero_and_does_not_normalize_worker_failure() {
        let _lock = LOCK.lock();
        let _reset = unsafe { Reset(ENCRYPT_UPDATE, DECRYPT_UPDATE) };
        unsafe { ENCRYPT_UPDATE = encrypt; DECRYPT_UPDATE = decrypt; }
        // Adjacent words deliberately disagree: the flag is target offset +8.
        for flag in [0, 1, 2, 0x8000_0000, u32::MAX] {
            let mut ctx = [u32::MAX, u32::MAX, flag, 0];
            let mut length = -1;
            let result = unsafe {
                evp_cipher_update(ctx.as_mut_ptr(), core::ptr::null_mut(),
                    &mut length, core::ptr::null(), 0)
            };
            assert_eq!((result, length), if flag == 0 { (1, 0) } else { (-7, 16) });
            assert_eq!(ctx, [u32::MAX, u32::MAX, flag, 0]);
        }
    }
}
