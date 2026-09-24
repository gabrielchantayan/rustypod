//! SHA-1 context update wrapper.
//!
//! `sha1_update_context` — original: `FUN_08103f1c` @ **0x08103f1c**.
//! Raw osos.dec words establish the 20-byte extent `0x08103f1c..0x08103f2f`:
//! `push {r4,lr}`, `add r0,r0,#0x1c`, `bl 0x08065224`, `mov r0,#0`, and
//! `pop {r4,pc}`. `0x08103f30` begins the next real function with
//! `push {r4,r5,r6,lr}`. Full-image A32 decoding finds three inbound plain
//! `bl` instructions (at `0x082358c0`, `0x08235a00`, and `0x08235a84`) and no
//! predicated inbound forms; the body has one plain direct `bl` and no
//! predicated direct calls.
//!
//! The wrapper advances its opaque owner to its embedded SHA-1 context at
//! `+0x1c`, forwards the input pointer and byte count unchanged to the legacy
//! SHA-1 update worker, discards that worker's result, and returns zero.
//! Deliberate deviation: the worker remains the existing replaceable seam
//! because its full implementation is not yet ported; this wrapper preserves
//! the retail ABI-visible forwarding and return value.

use super::sha1_update_payload::legacy_sha1_update;

/// Forwards an owner's embedded SHA-1 context to the legacy update worker.
///
/// # Safety
///
/// `owner.add(0x1c)`, `input`, and `input_len` must satisfy the worker's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sha1_update_context(
    owner: *mut u8,
    input: *const u8,
    input_len: u32,
) -> u32 {
    unsafe {
        legacy_sha1_update()(owner.add(0x1c), input, input_len);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::crypto::sha1_update_payload::{LegacySha1UpdateFn, LEGACY_SHA1_UPDATE};
    use crate::crypto::sha1_update_payload::tests::SHA1_UPDATE_TEST_LOCK;
    use core::ptr;

    static mut RECEIVED_CONTEXT: *mut u8 = ptr::null_mut();
    static mut RECEIVED_INPUT: *const u8 = ptr::null();
    static mut RECEIVED_LEN: u32 = 0;

    unsafe extern "C" fn record_update(context: *mut u8, input: *const u8, input_len: u32) -> u32 {
        unsafe {
            RECEIVED_CONTEXT = context;
            RECEIVED_INPUT = input;
            RECEIVED_LEN = input_len;
        }
        1
    }

    fn install_recording_worker() -> LegacySha1UpdateFn {
        let saved = unsafe { LEGACY_SHA1_UPDATE };
        unsafe { LEGACY_SHA1_UPDATE = record_update };
        saved
    }

    #[test]
    fn forwards_zero_length_and_discards_worker_result() {
        let _lock = SHA1_UPDATE_TEST_LOCK.lock();
        let saved = install_recording_worker();
        let mut owner = [0u8; 0x1c];
        let input = [0x11u8, 0x22, 0x33];

        let returned = unsafe { sha1_update_context(owner.as_mut_ptr(), input.as_ptr(), 0) };

        unsafe { LEGACY_SHA1_UPDATE = saved };
        assert_eq!(returned, 0);
        assert_eq!(unsafe { RECEIVED_CONTEXT }, unsafe { owner.as_mut_ptr().add(0x1c) });
        assert_eq!(unsafe { RECEIVED_INPUT }, input.as_ptr());
        assert_eq!(unsafe { RECEIVED_LEN }, 0);
    }

    #[test]
    fn forwards_nonzero_length_without_inspecting_input() {
        let _lock = SHA1_UPDATE_TEST_LOCK.lock();
        let saved = install_recording_worker();
        let mut owner = [0u8; 0x20];
        let input = [0xa5u8; 7];

        unsafe { sha1_update_context(owner.as_mut_ptr(), input.as_ptr(), input.len() as u32) };

        unsafe { LEGACY_SHA1_UPDATE = saved };
        assert_eq!(unsafe { RECEIVED_CONTEXT }, unsafe { owner.as_mut_ptr().add(0x1c) });
        assert_eq!(unsafe { RECEIVED_INPUT }, input.as_ptr());
        assert_eq!(unsafe { RECEIVED_LEN }, 7);
    }
}
