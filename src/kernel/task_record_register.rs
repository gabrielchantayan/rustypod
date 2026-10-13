//! Task-record registration — load address 0x08037e38, true size 8 bytes.
//! Raw words e51ff004/22003d00 form a literal veneer; the next entry is
//! 0x08037e40. Full-image ARM decoding finds two plain BL calls (0x08056430,
//! 0x08056644), zero predicated BL calls. IRAM 0x22003d00 mirrors osos
//! 0x08003d00: its 40-byte body stores selector 41, task id, and record at
//! request words 0, 2, and 7, then dispatches without loading a result.
//! Deliberate deviations: Rust replaces the literal transfer and mirrored
//! stack builder with a call through the existing message-dispatch seam.
//! Unwritten request words remain uninitialized; native pointers are narrowed
//! only at the target-width wire boundary. No task-id or NULL guard is added.

use core::mem::MaybeUninit;
use crate::kernel::task::TaskRecord;
use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// Register a task record; id zero denotes the caller's current task.
///
/// # Safety
/// `record` must satisfy the retailOS dispatcher's task-record lifetime and
/// layout requirements. The dispatcher must be installed on hosts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_record_register(task_id: u32, record: *mut TaskRecord) {
    register_with(task_id, record as usize as u32, message_dispatch_veneer);
}

#[inline(always)]
unsafe fn register_with(task_id: u32, record: u32, dispatch: unsafe extern "C" fn(*mut u32)) {
    let mut frame = [MaybeUninit::<u32>::uninit(); 9];
    let request = frame.as_mut_ptr().cast::<u32>().add(1);
    request.add(2).write(task_id);
    request.write(41);
    request.add(7).write(record);
    dispatch(request);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RECORDS: [u32; 3] = [0; 3];

    unsafe extern "C" fn service41(request: *mut u32) {
        assert_eq!(request.read(), 41);
        let id = request.add(2).read();
        let slot = if id == 0 { 1 } else { id as usize };
        core::ptr::addr_of_mut!(RECORDS).cast::<u32>().add(slot).write(request.add(7).read());
        // No request result is consumed by the wrapper.
        request.write(0xffff_ffff);
    }

    #[test]
    fn current_task_registration_replaces_record_and_accepts_null() {
        let _lock = LOCK.lock();
        unsafe {
            RECORDS = [0x11, 0x22, 0x33];
            register_with(0, 0xffff_fffc, service41);
            assert_eq!(RECORDS, [0x11, 0xffff_fffc, 0x33]);
            register_with(0, 0, service41);
            assert_eq!(RECORDS, [0x11, 0, 0x33]);
        }
    }

    #[test]
    fn explicit_task_registration_leaves_current_task_untouched() {
        let _lock = LOCK.lock();
        unsafe {
            RECORDS = [0x11, 0x22, 0x33];
            register_with(2, 0x8000_0000, service41);
            assert_eq!(RECORDS, [0x11, 0x22, 0x8000_0000]);
        }
    }
}
