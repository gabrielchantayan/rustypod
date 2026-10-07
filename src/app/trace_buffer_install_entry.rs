//! Trace-buffer entry installation, FUN_0814a1c0 @ 0x0814a1c0.
//! True extent [0x0814a1c0,0x0814a298): 216 executable bytes, no literals.
//! Raw A32: two incoming plain BLs, ten outgoing plain BLs, no predicated
//! BLs in either direction. Lock the table at +28, reject invalid/occupied
//! slots, allocate and construct an 88- or 96-byte owner, publish its returned
//! pointer, notify pending work, and unlock on every normal return.
//! Returns 2 for rejection, 25 for a NULL constructor result, otherwise 0.
//! Deviations: target words stay four bytes on hosts; host synchronization
//! must be supplied explicitly. The unported derived constructor remains a
//! verified resident call (Ghidra incorrectly declares its pointer return void).

//! Existing Rust presence_matches has opposite polarity to raw 0x08149f68:
//! pass zero to that API to reproduce retail's r2=1 empty-slot check.
//! Codegen: match.py exits 1 (54 original / 52 Rust instructions including
//! literals). LLVM selects allocation size and constructor then uses BLX;
//! slot publication, error values, notification and shared unlock remain.
use super::buffer_pool_owner_construct::buffer_pool_owner_construct;
use super::trace_buffer::trace_buffer_slot_presence_matches;
use crate::heap::veneers::operator_new;

pub type EntryConstruct = unsafe extern "C" fn(*mut u8, u32, u32, u32, u32, u32, u32) -> *mut u8;

#[derive(Clone, Copy)]
pub struct TraceBufferInstallOps {
    pub lock: unsafe extern "C" fn(*mut u8),
    pub unlock: unsafe extern "C" fn(*mut u8),
    pub notify: unsafe extern "C" fn(*mut u8),
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
    pub base: EntryConstruct,
    pub derived: EntryConstruct,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn lock(buffer: *mut u8) {
    let mut guard = core::ptr::null_mut();
    crate::kernel::sync_mutex::counted_mutex_guard_acquire_lock(&mut guard, buffer.add(28).cast());
}
#[cfg(target_os = "none")]
unsafe extern "C" fn unlock(buffer: *mut u8) {
    crate::kernel::sync_mutex::mutex_unlock_counted(buffer.add(28).cast());
}
#[cfg(target_os = "none")]
unsafe extern "C" fn notify(buffer: *mut u8) {
    super::work_pending_notify::work_pending_notify(buffer.cast());
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sync(_: *mut u8) { panic!("install target-word trace buffer synchronization") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_derived(_: *mut u8, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32) -> *mut u8 {
    panic!("install resident derived buffer owner constructor")
}
#[cfg(not(target_os = "none"))]
pub static mut TRACE_BUFFER_INSTALL_OPS: TraceBufferInstallOps = TraceBufferInstallOps {
    lock: missing_sync, unlock: missing_sync, notify: missing_sync,
    allocate: operator_new, base: buffer_pool_owner_construct, derived: missing_derived,
};

/// Install an owner in one of seven aligned target-word slots.
///
/// # Safety
/// Buffer must be a live retail trace buffer; constructors require valid
/// interface/context words. Host operations must implement its target layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn trace_buffer_install_entry(
    buffer: *mut u8, interface: u32, mode: u32, parameter: u32,
    limit: u32, child_context: u32, selector: u32, flag: u32, derived: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    let ops = TraceBufferInstallOps { lock, unlock, notify, allocate: operator_new,
        base: buffer_pool_owner_construct, derived: core::mem::transmute(0x081e_fc28usize) };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(TRACE_BUFFER_INSTALL_OPS).read_volatile();
    install(buffer, interface, mode, parameter, limit, child_context, selector, flag, derived, ops)
}

unsafe fn install(buffer: *mut u8, interface: u32, mode: u32, parameter: u32,
    limit: u32, child_context: u32, selector: u32, flag: u32, derived: u32,
    ops: TraceBufferInstallOps) -> u32 {
    (ops.lock)(buffer);
    let result = if trace_buffer_slot_presence_matches(buffer.cast(), selector, 0) != 0 {
        2
    } else {
        let (size, constructor) = if derived == 0 { (88, ops.base) } else { (96, ops.derived) };
        let owner = constructor((ops.allocate)(size), interface, mode, parameter, limit, child_context, flag);
        if owner.is_null() {
            25
        } else {
            buffer.cast::<u32>().add(selector as usize).write(owner as usize as u32);
            (ops.notify)(buffer);
            0
        }
    };
    (ops.unlock)(buffer);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "C" fn lock(buffer: *mut u8) { buffer.cast::<u32>().add(7).write(1); }
    unsafe extern "C" fn unlock(buffer: *mut u8) {
        assert_eq!(buffer.cast::<u32>().add(7).read(), 1);
        buffer.cast::<u32>().add(7).write(0);
    }
    unsafe extern "C" fn notify(buffer: *mut u8) {
        assert_eq!(buffer.cast::<u32>().add(7).read(), 1);
        assert!(core::slice::from_raw_parts(buffer.cast::<u32>(), 7).contains(&0x1234));
        buffer.cast::<u32>().add(8).write(1);
    }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 { size as *mut u8 }
    unsafe extern "C" fn base(block: *mut u8, _: u32, mode: u32, _: u32, _: u32, _: u32, _: u32) -> *mut u8 {
        assert_eq!(block as usize, 88);
        if mode == 0 { core::ptr::null_mut() } else { 0x1234 as *mut u8 }
    }
    unsafe extern "C" fn derived(block: *mut u8, _: u32, mode: u32, _: u32, _: u32, _: u32, _: u32) -> *mut u8 {
        assert_eq!(block as usize, 96);
        if mode == 0 { core::ptr::null_mut() } else { 0x1234 as *mut u8 }
    }
    #[test]
    fn rejection_failure_and_publication_preserve_other_slots_and_release_lock() {
        let ops = TraceBufferInstallOps { lock, unlock, notify, allocate, base, derived };
        for selector in [0, 6, 7, u32::MAX] {
            for occupied in [false, true] {
                for mode in [0, 1] {
                    for extended in [0, 1, u32::MAX] {
                        let mut words = [0u32; 9];
                        if occupied { words[..7].fill(0x5678); }
                        let before = words;
                        let result = unsafe { install(words.as_mut_ptr().cast(), 1, mode, 2, 3, 4,
                            selector, 5, extended, ops) };
                        let expected = if selector >= 7 || occupied { 2 } else if mode == 0 { 25 } else { 0 };
                        assert_eq!(result, expected);
                        assert_eq!(words[7], 0);
                        assert_eq!(words[8], u32::from(expected == 0));
                        for index in 0..7 {
                            assert_eq!(words[index], if expected == 0 && index == selector as usize { 0x1234 } else { before[index] });
                        }
                    }
                }
            }
        }
    }
}
