//! Submit a prepared request to a managed entry.
//!
//! `FUN_08041038` at `0x08041038` is a 200-byte ARM body ending at
//! `0x08041100`; its literal pool occupies that final word and the next
//! function begins at `0x08041104`. Raw A32 decoding finds three outbound
//! plain `bl` instructions (`0x08041088`, `0x080410ac`, and `0x080410f4`), no
//! predicated `bl`, and three inbound plain `bl` call sites
//! (`0x080473c8`, `0x080482b4`, and `0x080485d0`).
//!
//! The owner slot supplies a managed-entry pointer. The routine prepares the
//! request payload at `+0x1c`, submits the prepared scratch entry, then marks
//! the managed entry active by incrementing `+0x34`, decrementing `+0x10`, and
//! setting bit zero at `+0x2c`; it clears request word `+0x04` on success.
//! Any preparation or submission failure releases the scratch entry before
//! returning that status. A null owner slot or request returns `-50`; a null
//! managed entry releases a zeroed scratch entry and returns `0x302`.
//!
//! Deliberate deviation: the three unrecovered callees retain fixed-address
//! target dispatches. Host tests install a single operation seam; no callee
//! identity is asserted.

#[cfg(not(target_os = "none"))]
use core::ptr;

const REQUEST_PAYLOAD_OFFSET: usize = 0x1c;
const REQUEST_WORD_OFFSET: usize = 0x04;
const PREPARED_ENTRY_SIZE: usize = 0x14;
const PREPARE_BUFFER_SIZE: usize = 0x80;
const NULL_ARGUMENT_STATUS: i32 = -50;
const NULL_MANAGED_ENTRY_STATUS: i32 = 0x302;
const PREPARE_ADDRESS: usize = 0x0806_61e0;
const SUBMIT_ADDRESS: usize = 0x0804_8b68;
const RELEASE_ADDRESS: usize = 0x0806_45b8;

type PrepareRequest = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, *mut u8, *mut u8, *mut u16) -> i32;
type SubmitPreparedRequest = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, u16, u32) -> i32;
type ReleasePreparedEntry = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8, _: *mut u16) -> i32 {
    panic!("managed_entry_request_submit requires installed operation seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_submit(_: *mut u8, _: *mut u8, _: *mut u8, _: u16, _: u32) -> i32 {
    panic!("managed_entry_request_submit requires installed operation seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_: *mut u8, _: *mut u8) {
    panic!("managed_entry_request_submit requires installed operation seam")
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ManagedEntryRequestSubmitOps {
    pub prepare: PrepareRequest,
    pub submit: SubmitPreparedRequest,
    pub release: ReleasePreparedEntry,
}

#[cfg(not(target_os = "none"))]
pub static mut MANAGED_ENTRY_REQUEST_SUBMIT_OPS: ManagedEntryRequestSubmitOps = ManagedEntryRequestSubmitOps {
    prepare: missing_prepare,
    submit: missing_submit,
    release: missing_release,
};

#[inline(always)]
unsafe fn prepare_request(manager: *mut u8, request_payload: *mut u8, buffer: *mut u8, prepared_entry: *mut u8, scratch: *mut u8, identifier: *mut u16) -> i32 {
    #[cfg(target_os = "none")]
    return core::mem::transmute::<usize, PrepareRequest>(PREPARE_ADDRESS)(manager, request_payload, buffer, prepared_entry, scratch, identifier);
    #[cfg(not(target_os = "none"))]
    return (ptr::addr_of!(MANAGED_ENTRY_REQUEST_SUBMIT_OPS).read_volatile().prepare)(manager, request_payload, buffer, prepared_entry, scratch, identifier);
}

#[inline(always)]
unsafe fn submit_prepared_request(manager: *mut u8, buffer: *mut u8, scratch: *mut u8, identifier: u16) -> i32 {
    #[cfg(target_os = "none")]
    return core::mem::transmute::<usize, SubmitPreparedRequest>(SUBMIT_ADDRESS)(manager, buffer, scratch, identifier, 1);
    #[cfg(not(target_os = "none"))]
    return (ptr::addr_of!(MANAGED_ENTRY_REQUEST_SUBMIT_OPS).read_volatile().submit)(manager, buffer, scratch, identifier, 1);
}

#[inline(always)]
unsafe fn release_prepared_entry(manager: *mut u8, scratch: *mut u8) {
    #[cfg(target_os = "none")]
    return core::mem::transmute::<usize, ReleasePreparedEntry>(RELEASE_ADDRESS)(manager, scratch);
    #[cfg(not(target_os = "none"))]
    return (ptr::addr_of!(MANAGED_ENTRY_REQUEST_SUBMIT_OPS).read_volatile().release)(manager, scratch);
}

/// # Safety
///
/// `owner_slot` must point to a readable managed-entry pointer and `request`
/// must designate writable request storage through `+0x1c`. On success the
/// managed entry needs readable and writable words at `+0x10`, `+0x2c`, and
/// `+0x34`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.managed_entry_request_submit")]
#[inline(never)]
pub unsafe extern "C" fn managed_entry_request_submit(owner_slot: *mut *mut u8, request: *mut u8) -> i32 {
    if owner_slot.is_null() || request.is_null() {
        return NULL_ARGUMENT_STATUS;
    }

    let manager = owner_slot.read();
    let mut scratch = [0u8; PREPARED_ENTRY_SIZE];
    if manager.is_null() {
        release_prepared_entry(manager, scratch.as_mut_ptr());
        return NULL_MANAGED_ENTRY_STATUS;
    }

    let mut buffer = [0u8; PREPARE_BUFFER_SIZE];
    let mut identifier = 0u16;
    let status = prepare_request(manager, request.add(REQUEST_PAYLOAD_OFFSET), buffer.as_mut_ptr(), scratch.as_mut_ptr().add(4), scratch.as_mut_ptr(), &mut identifier);
    if status != 0 {
        release_prepared_entry(manager, scratch.as_mut_ptr());
        return status;
    }

    let status = submit_prepared_request(manager, buffer.as_mut_ptr(), scratch.as_mut_ptr(), identifier);
    if status != 0 {
        release_prepared_entry(manager, scratch.as_mut_ptr());
        return status;
    }

    let words = manager.cast::<u32>();
    words.add(13).write_volatile(words.add(13).read_volatile().wrapping_add(1));
    words.add(4).write_volatile(words.add(4).read_volatile().wrapping_sub(1));
    words.add(11).write_volatile(words.add(11).read_volatile() | 1);
    request.add(REQUEST_WORD_OFFSET).cast::<u32>().write(0);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static LOG: Mutex<(i32, i32, usize, usize, u16, u32, u32)> = Mutex::new((0, 0, 0, 0, 0, 0, 0));

    unsafe extern "C" fn prepare(_: *mut u8, payload: *mut u8, buffer: *mut u8, entry: *mut u8, scratch: *mut u8, identifier: *mut u16) -> i32 {
        let mut log = LOG.lock();
        log.2 = payload as usize;
        log.3 = entry.offset_from(scratch) as usize;
        buffer.write(0xa5);
        identifier.write(0x8142);
        log.0
    }
    unsafe extern "C" fn submit(_: *mut u8, buffer: *mut u8, _: *mut u8, identifier: u16, mode: u32) -> i32 {
        let mut log = LOG.lock();
        log.4 = identifier;
        log.5 = mode;
        log.6 = buffer.read() as u32;
        log.1
    }
    unsafe extern "C" fn release(_: *mut u8, _: *mut u8) { LOG.lock().6 += 0x100; }

    struct OpsGuard { _lock: MutexGuard<'static, ()>, old: ManagedEntryRequestSubmitOps }
    impl Drop for OpsGuard {
        fn drop(&mut self) { unsafe { ptr::addr_of_mut!(MANAGED_ENTRY_REQUEST_SUBMIT_OPS).write_volatile(self.old); } }
    }
    fn install(prepare_status: i32, submit_status: i32) -> OpsGuard {
        let lock = OPS_LOCK.lock();
        let old = unsafe { ptr::addr_of!(MANAGED_ENTRY_REQUEST_SUBMIT_OPS).read_volatile() };
        unsafe { ptr::addr_of_mut!(MANAGED_ENTRY_REQUEST_SUBMIT_OPS).write_volatile(ManagedEntryRequestSubmitOps { prepare, submit, release }); }
        *LOG.lock() = (prepare_status, submit_status, 0, 0, 0, 0, 0);
        OpsGuard { _lock: lock, old }
    }

    #[test]
    fn rejects_null_arguments_without_operations() {
        assert_eq!(unsafe { managed_entry_request_submit(ptr::null_mut(), ptr::null_mut()) }, NULL_ARGUMENT_STATUS);
    }

    #[test]
    fn releases_null_managed_entry() {
        let _ops = install(0, 0);
        let mut manager = ptr::null_mut();
        assert_eq!(unsafe { managed_entry_request_submit(&mut manager, [0u8; 32].as_mut_ptr()) }, NULL_MANAGED_ENTRY_STATUS);
        assert_eq!(LOG.lock().6, 0x100);
    }

    #[test]
    fn failures_release_the_scratch_entry() {
        let _ops = install(-7, 0);
        let mut words = [0u32; 14];
        let mut manager = words.as_mut_ptr().cast::<u8>();
        let mut request = [0u8; 32];
        assert_eq!(unsafe { managed_entry_request_submit(&mut manager, request.as_mut_ptr()) }, -7);
        assert_eq!(LOG.lock().6, 0x100);
    }

    #[test]
    fn success_forwards_prepared_state_and_updates_manager() {
        let _ops = install(0, 0);
        let mut words = [0u32; 14];
        words[4] = 9;
        words[11] = 0x40;
        words[13] = 7;
        let mut manager = words.as_mut_ptr().cast::<u8>();
        let mut request = [0u8; 32];
        request[4..8].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert_eq!(unsafe { managed_entry_request_submit(&mut manager, request.as_mut_ptr()) }, 0);
        let log = LOG.lock();
        assert_eq!((log.2, log.3, log.4, log.5, log.6), (request.as_mut_ptr().wrapping_add(0x1c) as usize, 4, 0x8142, 1, 0xa5));
        assert_eq!((words[4], words[11], words[13]), (8, 0x41, 8));
        assert_eq!(u32::from_le_bytes(request[4..8].try_into().unwrap()), 0);
    }
}
