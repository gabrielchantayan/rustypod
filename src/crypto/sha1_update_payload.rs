//! SHA-1 update payload wrapper.
//!
//! `sha1_update_payload` — original: `FUN_08273618` @ **0x08273618**
//! (20 bytes exactly, five ARM words `0x08273618..0x0827362b`; the next
//! function opens with `push {r0,r1,r4-r11,lr}` at `0x0827362c`). Raw ARM
//! decoding finds three unconditional inbound `bl` instructions and no
//! predicated inbound `bl` instructions.
//!
//! The wrapper shifts its opaque owner pointer by four bytes and forwards the
//! unchanged input pointer and byte count to the legacy SHA-1 update worker at
//! `0x08065224`; it discards that worker's success result and returns zero.
//! Deliberate deviation: the worker remains a replaceable seam because it is
//! not yet ported; the wrapper retains its ABI-visible argument forwarding and
//! zero return.

/// Legacy SHA-1 update worker at `0x08065224`.
pub type LegacySha1UpdateFn = unsafe extern "C" fn(*mut u8, *const u8, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_legacy_sha1_update(
    context: *mut u8,
    input: *const u8,
    input_len: u32,
) -> u32 {
    let update: LegacySha1UpdateFn = unsafe { core::mem::transmute(0x0806_5224usize) };
    unsafe { update(context, input, input_len) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_legacy_sha1_update(
    _context: *mut u8,
    _input: *const u8,
    _input_len: u32,
) -> u32 {
    panic!("sha1_update_payload requires legacy SHA-1 update worker 0x08065224")
}

#[cfg(target_os = "none")]
pub static mut LEGACY_SHA1_UPDATE: LegacySha1UpdateFn = firmware_legacy_sha1_update;
#[cfg(not(target_os = "none"))]
pub static mut LEGACY_SHA1_UPDATE: LegacySha1UpdateFn = missing_legacy_sha1_update;

#[inline(always)]
unsafe fn legacy_sha1_update() -> LegacySha1UpdateFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LEGACY_SHA1_UPDATE)) }
}

/// Forwards an owner payload to retailOS's legacy SHA-1 update worker.
///
/// # Safety
///
/// `owner.add(4)`, `input`, and `input_len` must satisfy the worker's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sha1_update_payload(
    owner: *mut u8,
    input: *const u8,
    input_len: u32,
) -> u32 {
    unsafe {
        legacy_sha1_update()(owner.add(4), input, input_len);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static SHA1_UPDATE_PAYLOAD_TEST_LOCK: Mutex<()> = Mutex::new(());
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

    #[test]
    fn forwards_payload_arguments_and_discards_worker_result() {
        let _lock = SHA1_UPDATE_PAYLOAD_TEST_LOCK.lock();
        let saved = unsafe { LEGACY_SHA1_UPDATE };
        unsafe { LEGACY_SHA1_UPDATE = record_update };

        let mut owner = [0u8; 8];
        let input = [0x11u8, 0x22, 0x33];
        let returned = unsafe { sha1_update_payload(owner.as_mut_ptr(), input.as_ptr(), 0) };

        unsafe { LEGACY_SHA1_UPDATE = saved };
        assert_eq!(returned, 0);
        assert_eq!(unsafe { RECEIVED_CONTEXT }, unsafe { owner.as_mut_ptr().add(4) });
        assert_eq!(unsafe { RECEIVED_INPUT }, input.as_ptr());
        assert_eq!(unsafe { RECEIVED_LEN }, 0);
    }

    #[test]
    fn forwards_nonzero_length_without_inspecting_input() {
        let _lock = SHA1_UPDATE_PAYLOAD_TEST_LOCK.lock();
        let saved = unsafe { LEGACY_SHA1_UPDATE };
        unsafe { LEGACY_SHA1_UPDATE = record_update };

        let mut owner = [0u8; 8];
        let input = [0xa5u8; 7];
        unsafe { sha1_update_payload(owner.as_mut_ptr(), input.as_ptr(), input.len() as u32) };

        unsafe { LEGACY_SHA1_UPDATE = saved };
        assert_eq!(unsafe { RECEIVED_LEN }, 7);
    }
}
