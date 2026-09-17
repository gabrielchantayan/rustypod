//! USB transfer-slot scheduling — original: `FUN_082937c0` @ `0x082937c0`
//! (172 bytes: 172 bytes of ARM code through `bx lr` at `0x08293868`, then
//! the table-address literal at `0x0829386c`; the next real function starts
//! at `0x08293870`).
//!
//! Raw ARM decoding verifies four inbound direct plain `bl` call sites and no
//! predicated `bl` call sites. The body makes three outbound plain calls:
//! `four_slot_key_index`, `usb_high_speed_mode_active` when `packet_size` is
//! zero, and the still-retail USB transfer submitter at `0x081071ec`.
//!
//! It finds the keyed 24-byte runtime slot, clears its transfer-kind flags,
//! chooses a 64-byte full-speed or 512-byte high-speed default packet size,
//! submits the transfer using `request + 0x34`, then records a positive result
//! or clears the result word and returns its signed low byte on failure.
//!
//! Deliberate deviations: the unported submitter is a raw target call; host
//! builds use a replaceable submit seam. The live target slot table is accessed
//! through its documented `0x089d04c4` address; host tests provide slots through
//! the lookup seam.

const SLOT_SIZE: usize = 0x18;
const SLOT_TABLE_ADDRESS: usize = 0x089d_04c4;
const DEFAULT_FULL_SPEED_PACKET_SIZE: u32 = 0x40;
const DEFAULT_HIGH_SPEED_PACKET_SIZE: u32 = 0x200;

#[cfg(target_os = "none")]
unsafe fn submit_usb_transfer(request_channel: u32, key: u32, transfer_kind: u32, packet_size: u32, completion: u32) -> i32 {
    let submit: unsafe extern "C" fn(u32, u32, u32, u32, u32) -> i32 = unsafe { core::mem::transmute(0x0810_71ecusize) };
    unsafe { submit(request_channel, key, transfer_kind, packet_size, completion) }
}
#[cfg(not(target_os = "none"))]
struct HostOps { find_slot: unsafe extern "C" fn(u32) -> *mut u8, high_speed_active: unsafe extern "C" fn() -> u32, submit: unsafe extern "C" fn(u32, u32, u32, u32, u32) -> i32 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_slot(_key: u32) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_high_speed() -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_submit(_channel: u32, _key: u32, _kind: u32, _size: u32, _completion: u32) -> i32 { -1 }
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps { find_slot: missing_slot, high_speed_active: missing_high_speed, submit: missing_submit };

/// Schedules one keyed USB transfer and records its submit result in the matching runtime slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_transfer_schedule(request: *const u8, key: u32, transfer_kind: u32, mut packet_size: u32, _transfer_flag: u32, completion: u32) -> i32 {
    #[cfg(target_os = "none")]
    let slot = {
        let index = unsafe { crate::app::four_slot_key_index::four_slot_key_index(request.cast_mut(), key) };
        if index < 0 { return -1; }
        unsafe { (SLOT_TABLE_ADDRESS as *mut u8).add(index as usize * SLOT_SIZE) }
    };
    #[cfg(not(target_os = "none"))]
    let slot = unsafe { (HOST_OPS.find_slot)(key) };
    if slot.is_null() { return -1; }
    unsafe {
        slot.add(0x11).write(0); slot.add(0x12).write(0);
        if transfer_kind == 1 { slot.add(0x11).write(1); } else if transfer_kind == 3 { slot.add(0x12).write(1); }
    }
    if packet_size == 0 {
        #[cfg(target_os = "none")]
        let high_speed = unsafe { crate::drivers::usb_high_speed_mode::usb_high_speed_mode_active() };
        #[cfg(not(target_os = "none"))]
        let high_speed = unsafe { (HOST_OPS.high_speed_active)() };
        packet_size = if high_speed == 0 { DEFAULT_FULL_SPEED_PACKET_SIZE } else { DEFAULT_HIGH_SPEED_PACKET_SIZE };
    }
    let request_channel = unsafe { request.add(0x34).cast::<u32>().read() };
    #[cfg(target_os = "none")]
    let result = unsafe { submit_usb_transfer(request_channel, key, transfer_kind, packet_size, completion) };
    #[cfg(not(target_os = "none"))]
    let result = unsafe { (HOST_OPS.submit)(request_channel, key, transfer_kind, packet_size, completion) };
    unsafe { slot.add(0xc).cast::<i32>().write(if result > 0 { result } else { 0 }); }
    if result > 0 { 0 } else { result as i8 as i32 }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut SLOT: [u8; SLOT_SIZE] = [0; SLOT_SIZE]; static mut EXPECTED_KEY: u32 = 0; static mut HIGH_SPEED: u32 = 0; static mut RESULT: i32 = 0; static mut SUBMIT_ARGS: [u32; 5] = [0; 5];
    unsafe extern "C" fn find_slot(key: u32) -> *mut u8 { if key == unsafe { EXPECTED_KEY } { core::ptr::addr_of_mut!(SLOT).cast() } else { core::ptr::null_mut() } }
    unsafe extern "C" fn high_speed() -> u32 { unsafe { HIGH_SPEED } }
    unsafe extern "C" fn submit(channel: u32, key: u32, kind: u32, size: u32, completion: u32) -> i32 { unsafe { SUBMIT_ARGS = [channel, key, kind, size, completion]; RESULT } }
    fn install(key: u32, high_speed_active: u32, result: i32) { unsafe { SLOT = [0; SLOT_SIZE]; EXPECTED_KEY = key; HIGH_SPEED = high_speed_active; RESULT = result; SUBMIT_ARGS = [0; 5]; HOST_OPS = HostOps { find_slot, high_speed_active: high_speed, submit }; } }
    #[test]
    fn schedules_kind_and_default_packet_size() {
        let _lock = LOCK.lock(); install(0x83, 0, 7); let mut request = [0u8; 0x38]; request[0x34..0x38].copy_from_slice(&0x1234_5678u32.to_ne_bytes());
        assert_eq!(unsafe { usb_transfer_schedule(request.as_ptr(), 0x83, 1, 0, 9, 3) }, 0);
        unsafe { assert_eq!(SLOT[0x11], 1); assert_eq!(SLOT[0x12], 0); assert_eq!(SLOT[0xc..0x10], 7i32.to_ne_bytes()); assert_eq!(SUBMIT_ARGS, [0x1234_5678, 0x83, 1, 0x40, 3]); }
    }
    #[test]
    fn preserves_explicit_size_and_signed_low_byte_failure() {
        let _lock = LOCK.lock(); install(2, 1, -257); let mut request = [0u8; 0x38]; request[0x34..0x38].copy_from_slice(&9u32.to_ne_bytes());
        assert_eq!(unsafe { usb_transfer_schedule(request.as_ptr(), 2, 3, 0x88, 0, 1) }, -1);
        unsafe { assert_eq!(SLOT[0x11], 0); assert_eq!(SLOT[0x12], 1); assert_eq!(SLOT[0xc..0x10], [0; 4]); assert_eq!(SUBMIT_ARGS, [9, 2, 3, 0x88, 1]); }
    }
    #[test]
    fn leaves_slots_untouched_when_key_is_absent() {
        let _lock = LOCK.lock(); install(1, 0, 4); let request = [0u8; 0x38]; assert_eq!(unsafe { usb_transfer_schedule(request.as_ptr(), 2, 1, 0, 0, 0) }, -1);
        unsafe { assert_eq!(SLOT, [0; SLOT_SIZE]); assert_eq!(SUBMIT_ARGS, [0; 5]); }
    }
}
