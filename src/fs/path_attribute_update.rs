//! Path-node attribute update.
//!
//! This is the small metadata-update gate used by the file layer after it has
//! resolved a pathname. It keeps the path node alive while its backing cache
//! header is changed and written.

use crate::drivers::{ata_cmd, ata_semaphore};
use crate::fs::{cache_block_prepare, path_drive_index, path_node};

/// Resident path lookup at `0x082e15d8`, not yet ported.
pub const PATH_NODE_LOOKUP_ADDRESS: usize = 0x082e_15d8;

/// ABI of the resident path-node lookup.
pub type PathNodeLookup = unsafe extern "C" fn(*const u8) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_path_node(path: *const u8) -> *mut u8 {
    let lookup: PathNodeLookup = core::mem::transmute(PATH_NODE_LOOKUP_ADDRESS);
    lookup(path)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_drive_index(_path: *const u8) -> i32 { -1 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_semaphore(_index: usize) -> usize { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_path_lookup(_path: *const u8) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_node: *mut u8, _dirty: u32, _timestamp: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_node: *mut u8) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_error(_error: u32) -> u32 { u32::MAX }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    drive_index: unsafe extern "C" fn(*const u8) -> i32,
    wait: unsafe extern "C" fn(usize) -> usize,
    lookup: PathNodeLookup,
    prepare: unsafe extern "C" fn(*mut u8, u32, u32) -> u32,
    release: unsafe extern "C" fn(*mut u8) -> *mut u8,
    signal: unsafe extern "C" fn(usize) -> usize,
    error: unsafe extern "C" fn(u32) -> u32,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: HostOps = HostOps {
    drive_index: missing_drive_index,
    wait: missing_semaphore,
    lookup: missing_path_lookup,
    prepare: missing_prepare,
    release: missing_release,
    signal: missing_semaphore,
    error: missing_error,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> HostOps { core::ptr::addr_of!(HOST_OPS).read_volatile() }

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_path_node(path: *const u8) -> *mut u8 {
    (host_ops().lookup)(path)
}

#[inline(always)]
unsafe fn resolve_drive_index(path: *const u8) -> i32 {
    #[cfg(target_os = "none")]
    { path_drive_index::resolve_path_drive_index(path) }
    #[cfg(not(target_os = "none"))]
    { (host_ops().drive_index)(path) }
}
#[inline(always)]
unsafe fn wait_for_drive(index: usize) {
    #[cfg(target_os = "none")]
    { ata_semaphore::ata_semaphore_wait(index); }
    #[cfg(not(target_os = "none"))]
    { (host_ops().wait)(index); }
}
#[inline(always)]
unsafe fn prepare_cache_block(node: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    { cache_block_prepare::cache_block_prepare(node, 0, 0) }
    #[cfg(not(target_os = "none"))]
    { (host_ops().prepare)(node, 0, 0) }
}
#[inline(always)]
unsafe fn release_path_node(node: *mut u8) {
    #[cfg(target_os = "none")]
    { path_node::path_node_release(node); }
    #[cfg(not(target_os = "none"))]
    { (host_ops().release)(node); }
}
#[inline(always)]
unsafe fn signal_drive(index: usize) {
    #[cfg(target_os = "none")]
    { ata_semaphore::ata_semaphore_signal(index); }
    #[cfg(not(target_os = "none"))]
    { (host_ops().signal)(index); }
}
#[inline(always)]
unsafe fn report_error(error: u32) {
    #[cfg(target_os = "none")]
    { ata_cmd::ata_report_error(error); }
    #[cfg(not(target_os = "none"))]
    { (host_ops().error)(error); }
}

/// update_path_attributes — original: `FUN_082e4578` @ `0x082e4578` (148
/// bytes; two verified direct `bl` call sites, both unconditional).
///
/// Resolves the drive index for `path`; failure returns zero without touching
/// the ATA error record. Otherwise holds that drive's ATA semaphore, finds the
/// path node, and updates header byte `node[1] + 0x0b` only when bits 3–4 are
/// unchanged. It then writes the cache block, releases the node, signals the
/// semaphore, and records error 28 exactly when the write returned zero.
///
/// Deliberate deviation: the unresolved path-node lookup remains an explicit
/// resident call at `0x082e15d8`; all other direct callees are existing ports.
/// Host builds replace every boundary with volatile-loaded test operations.
///
/// # Safety
///
/// `path` must meet the resident path parser's string ABI. A found node must
/// have a valid target-width header pointer at byte offset four.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn update_path_attributes(path: *const u8, attributes: u8) -> u32 {
    let index = resolve_drive_index(path);
    if index < 0 {
        return 0;
    }
    let index = index as usize;
    wait_for_drive(index);
    let node = lookup_path_node(path);
    let mut result = 0;
    let mut error = 2;
    if !node.is_null() {
        let header = node.add(4).cast::<u32>().read() as usize as *mut u8;
        if (attributes & 0x18) == (header.add(0x0b).read() & 0x18) {
            header.add(0x0b).write(attributes);
            result = prepare_cache_block(node);
            error = if result == 0 { 28 } else { 0 };
        }
        release_path_node(node);
    }
    signal_drive(index);
    report_error(error);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<std::vec::Vec<&'static str>> = Mutex::new(std::vec::Vec::new());
    static mut DRIVE_INDEX: i32 = 0;
    static mut NODE: *mut u8 = core::ptr::null_mut();
    static mut PREPARE_RESULT: u32 = 0;

    unsafe extern "C" fn drive_index(_: *const u8) -> i32 { EVENTS.lock().push("index"); DRIVE_INDEX }
    unsafe extern "C" fn wait(_: usize) -> usize { EVENTS.lock().push("wait"); 0 }
    unsafe extern "C" fn lookup(_: *const u8) -> *mut u8 { EVENTS.lock().push("lookup"); NODE }
    unsafe extern "C" fn prepare(_: *mut u8, dirty: u32, timestamp: u32) -> u32 { assert_eq!((dirty, timestamp), (0, 0)); EVENTS.lock().push("prepare"); PREPARE_RESULT }
    unsafe extern "C" fn release(_: *mut u8) -> *mut u8 { EVENTS.lock().push("release"); core::ptr::null_mut() }
    unsafe extern "C" fn signal(_: usize) -> usize { EVENTS.lock().push("signal"); 0 }
    unsafe extern "C" fn error(error: u32) -> u32 { EVENTS.lock().push(if error == 28 { "error28" } else if error == 2 { "error2" } else { "error0" }); u32::MAX }

    unsafe fn install() { HOST_OPS = HostOps { drive_index, wait, lookup, prepare, release, signal, error }; }
    fn reset() { EVENTS.lock().clear(); unsafe { DRIVE_INDEX = 0; NODE = core::ptr::null_mut(); PREPARE_RESULT = 0; install(); } }

    #[test]
    fn updates_matching_mode_and_reports_write_failure() {
        let _guard = OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::PATH_ATTRIBUTE_UPDATE, 0x1000) else { return };
        reset();
        unsafe {
            let node = slab;
            let header = slab.add(0x100);
            node.add(4).cast::<u32>().write(header as usize as u32);
            header.add(0x0b).write(0x18);
            NODE = node;
            PREPARE_RESULT = 0;
            assert_eq!(update_path_attributes(core::ptr::null(), 0x1a), 0);
            assert_eq!(header.add(0x0b).read(), 0x1a);
        }
        assert_eq!(*EVENTS.lock(), ["index", "wait", "lookup", "prepare", "release", "signal", "error28"]);
    }

    #[test]
    fn preserves_header_and_skips_write_when_mode_changes() {
        let _guard = OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::PATH_ATTRIBUTE_UPDATE_MODE_MISMATCH, 0x1000) else { return };
        reset();
        unsafe {
            let header = slab.add(0x100);
            slab.add(4).cast::<u32>().write(header as usize as u32);
            header.add(0x0b).write(0x08);
            NODE = slab;
            assert_eq!(update_path_attributes(core::ptr::null(), 0x10), 0);
            assert_eq!(header.add(0x0b).read(), 0x08);
        }
        assert_eq!(*EVENTS.lock(), ["index", "wait", "lookup", "release", "signal", "error2"]);
    }

    #[test]
    fn drive_resolution_failure_does_not_call_any_boundary() {
        let _guard = OPS_LOCK.lock();
        reset();
        unsafe { DRIVE_INDEX = -1; assert_eq!(update_path_attributes(core::ptr::null(), 0), 0); }
        assert_eq!(*EVENTS.lock(), ["index"]);
    }
}
