//! `global_adjustment_notification_post` — original: `FUN_08113da8` @
//! `0x08113da8` (116 bytes, `0x08113da8..0x08113e1c`; the literal pool
//! begins at `0x08113e1c` and the next independently decoded function starts
//! at `0x08113e38`).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM words establish five unconditional direct `bl` instructions
//! (`0x082ab31c`, `0x081bb450`, `0x082ab1c8`, `0x082ab338`, and
//! `0x081bb3a0`) and one predicated `blne` (`0x081bb29c`). The incoming first
//! argument is ignored. When global notification state bit 0 is clear, the
//! function acquires its global work cell, constructs and queues notification
//! kind `0x15e`, and releases the cell. It then submits the requested signed
//! adjustment with zero as its third argument. A nonzero result triggers the
//! final notification with argument one.
//!
//! # Deliberate deviations
//!
//! The six callees have no recovered semantic identities. Target builds call
//! their verified retailOS addresses; host builds use narrow callback seams.

/// ABI of the global work-cell acquisition target at `0x082ab31c`.
pub type GlobalAdjustmentAcquire = unsafe extern "C" fn(*mut u32) -> u32;
/// ABI of the notification construction target at `0x081bb450`.
pub type GlobalAdjustmentConstruct = unsafe extern "C" fn(*mut u8, u32, u32, *mut u8) -> *mut u8;
/// ABI of the constructed-notification queue target at `0x082ab1c8`.
pub type GlobalAdjustmentQueue = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> u32;
/// ABI of the global work-cell release target at `0x082ab338`.
pub type GlobalAdjustmentRelease = unsafe extern "C" fn(*mut u32);
/// ABI of the signed-adjustment submission target at `0x081bb3a0`.
pub type GlobalAdjustmentSubmit = unsafe extern "C" fn(*mut u32, i32, u32) -> u32;
/// ABI of the conditional completion notification target at `0x081bb29c`.
pub type GlobalAdjustmentNotify = unsafe extern "C" fn(u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_acquire(_cell: *mut u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_work: *mut u8, _kind: u32, _zero: u32, _context: *mut u8) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_queue(_notification: *mut u8, _callback: *mut u8, _work: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_cell: *mut u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_submit(_cell: *mut u32, _adjustment: i32, _zero: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_notify(_value: u32) {}

/// Host seams for the six unported retailOS targets.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_ACQUIRE: GlobalAdjustmentAcquire = missing_acquire;
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_CONSTRUCT: GlobalAdjustmentConstruct = missing_construct;
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_QUEUE: GlobalAdjustmentQueue = missing_queue;
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_RELEASE: GlobalAdjustmentRelease = missing_release;
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_SUBMIT: GlobalAdjustmentSubmit = missing_submit;
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_NOTIFY: GlobalAdjustmentNotify = missing_notify;

#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_STATE: [u32; 8] = [0; 8];
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_WORK_CELL: u32 = 0;
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_ADJUSTMENT_WORK: [u32; 8] = [0; 8];

#[inline(always)]
unsafe fn global_state_flags() -> u32 {
    #[cfg(target_os = "none")]
    return unsafe { core::ptr::read_volatile((0x089c_a660usize + 0x1c) as *const u32) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_ADJUSTMENT_STATE[7])) }
}

/// Posts the global adjustment notification, then submits `adjustment`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_adjustment_notification_post(_ignored: *mut u8, adjustment: i32) {
    #[cfg(target_os = "none")]
    let (work_cell, work, callback_context) = (0x089c_a67cusize as *mut u32, 0x089c_a09cusize as *mut u8, 0x08a1_b0bcusize as *mut u8);
    #[cfg(not(target_os = "none"))]
    let (work_cell, work, callback_context) = unsafe { (core::ptr::addr_of_mut!(GLOBAL_ADJUSTMENT_WORK_CELL), core::ptr::addr_of_mut!(GLOBAL_ADJUSTMENT_WORK).cast(), 0x08a1_b0bcusize as *mut u8) };

    #[cfg(target_os = "none")]
    let (acquire, construct, queue, release, submit, notify): (GlobalAdjustmentAcquire, GlobalAdjustmentConstruct, GlobalAdjustmentQueue, GlobalAdjustmentRelease, GlobalAdjustmentSubmit, GlobalAdjustmentNotify) = unsafe { (core::mem::transmute(0x082a_b31cusize), core::mem::transmute(0x081b_b450usize), core::mem::transmute(0x082a_b1c8usize), core::mem::transmute(0x082a_b338usize), core::mem::transmute(0x081b_b3a0usize), core::mem::transmute(0x081b_b29cusize)) };
    #[cfg(not(target_os = "none"))]
    let (acquire, construct, queue, release, submit, notify) = unsafe { (GLOBAL_ADJUSTMENT_ACQUIRE, GLOBAL_ADJUSTMENT_CONSTRUCT, GLOBAL_ADJUSTMENT_QUEUE, GLOBAL_ADJUSTMENT_RELEASE, GLOBAL_ADJUSTMENT_SUBMIT, GLOBAL_ADJUSTMENT_NOTIFY) };

    if unsafe { global_state_flags() } & 1 == 0 && unsafe { acquire(work_cell) } != 0 {
        let notification = unsafe { construct(work, 0x15e, 0, callback_context) };
        unsafe { queue(notification, 0x081b_0638usize as *mut u8, work) };
        unsafe { release(work_cell) };
    }
    if unsafe { submit(work_cell, adjustment, 0) } != 0 {
        unsafe { notify(1) };
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut LOG: [u32; 8] = [0; 8];
    unsafe extern "C" fn acquire(_cell: *mut u32) -> u32 { unsafe { LOG[0] += 1 }; 1 }
    unsafe extern "C" fn construct(_work: *mut u8, kind: u32, zero: u32, _context: *mut u8) -> *mut u8 { unsafe { LOG[1] = kind; LOG[2] = zero }; 0x1234usize as *mut u8 }
    unsafe extern "C" fn queue(notification: *mut u8, callback: *mut u8, _work: *mut u8) -> u32 { unsafe { LOG[3] = notification as u32; LOG[4] = callback as u32 }; 0 }
    unsafe extern "C" fn release(_cell: *mut u32) { unsafe { LOG[5] += 1 } }
    unsafe extern "C" fn submit(_cell: *mut u32, adjustment: i32, zero: u32) -> u32 { unsafe { LOG[6] = adjustment as u32; LOG[7] = zero }; 1 }
    unsafe extern "C" fn notify(value: u32) { unsafe { LOG[5] = value } }

    #[test]
    fn posts_when_unflagged_then_submits_signed_adjustment() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            LOG = [0; 8]; GLOBAL_ADJUSTMENT_STATE = [0; 8];
            GLOBAL_ADJUSTMENT_ACQUIRE = acquire; GLOBAL_ADJUSTMENT_CONSTRUCT = construct;
            GLOBAL_ADJUSTMENT_QUEUE = queue; GLOBAL_ADJUSTMENT_RELEASE = release;
            GLOBAL_ADJUSTMENT_SUBMIT = submit; GLOBAL_ADJUSTMENT_NOTIFY = notify;
            global_adjustment_notification_post(core::ptr::null_mut(), -7);
            assert_eq!(LOG, [1, 0x15e, 0, 0x1234, 0x081b0638, 1, (-7i32) as u32, 0]);
        }
    }

    #[test]
    fn flagged_state_skips_post_and_zero_submit_skips_notification() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            LOG = [0; 8]; GLOBAL_ADJUSTMENT_STATE = [0; 8];
            GLOBAL_ADJUSTMENT_STATE[7] = 1;
            GLOBAL_ADJUSTMENT_ACQUIRE = acquire; GLOBAL_ADJUSTMENT_CONSTRUCT = construct;
            GLOBAL_ADJUSTMENT_QUEUE = queue; GLOBAL_ADJUSTMENT_RELEASE = release;
            GLOBAL_ADJUSTMENT_SUBMIT = missing_submit; GLOBAL_ADJUSTMENT_NOTIFY = notify;
            global_adjustment_notification_post(core::ptr::null_mut(), 12);
            assert_eq!(LOG, [0, 0, 0, 0, 0, 0, 0, 0]);
        }
    }
}
