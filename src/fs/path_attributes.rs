//! Path-node attribute reader.
//!
//! Resolves a pathname through the selected drive and returns byte 0x0b of
//! its backing path-node header.

use crate::drivers::{ata_cmd, ata_semaphore};
use crate::fs::{path_drive_index, path_node};

/// Resident path lookup at `0x082e15d8`, not yet ported.
const PATH_NODE_LOOKUP_ADDRESS: usize = 0x082e_15d8;
type PathNodeLookup = unsafe extern "C" fn(*const u8) -> *mut u8;

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
unsafe extern "C" fn missing_release(_node: *mut u8) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_error(_error: u32) -> u32 { u32::MAX }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    drive_index: unsafe extern "C" fn(*const u8) -> i32,
    wait: unsafe extern "C" fn(usize) -> usize,
    lookup: PathNodeLookup,
    release: unsafe extern "C" fn(*mut u8) -> *mut u8,
    signal: unsafe extern "C" fn(usize) -> usize,
    error: unsafe extern "C" fn(u32) -> u32,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: HostOps = HostOps {
    drive_index: missing_drive_index,
    wait: missing_semaphore,
    lookup: missing_path_lookup,
    release: missing_release,
    signal: missing_semaphore,
    error: missing_error,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> HostOps { core::ptr::addr_of!(HOST_OPS).read_volatile() }

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
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_path_node(path: *const u8) -> *mut u8 { (host_ops().lookup)(path) }
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

/// read_path_attributes — original: `FUN_082e1d2c` @ `0x082e1d2c` (108
/// bytes; two verified direct `bl` call sites, both unconditional).
///
/// Resolves `path` to a drive index. A negative index returns false without
/// reporting an ATA error. Otherwise it locks that drive, looks up the path
/// node, copies header byte `+0x0b` to `attributes` when found, releases the
/// node, unlocks the drive, then reports error zero on success or two when no
/// node was found.
///
/// Deliberate deviation: the unported lookup remains a resident call at
/// `0x082e15d8`; host builds replace every boundary with recording operations.
///
/// # Safety
///
/// `path` must satisfy the resident parser ABI. `attributes` must be writable,
/// and a found node must contain a valid target-width header pointer at +4.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn read_path_attributes(path: *const u8, attributes: *mut u8) -> u32 {
    let index = resolve_drive_index(path);
    if index < 0 {
        return 0;
    }
    let index = index as usize;
    wait_for_drive(index);
    let node = lookup_path_node(path);
    let found = !node.is_null();
    if found {
        let header = node.add(4).cast::<u32>().read() as usize as *const u8;
        attributes.write(header.add(0x0b).read());
        release_path_node(node);
    }
    signal_drive(index);
    report_error(if found { 0 } else { 2 });
    found as u32
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

    unsafe extern "C" fn drive_index(_: *const u8) -> i32 { EVENTS.lock().push("index"); DRIVE_INDEX }
    unsafe extern "C" fn wait(_: usize) -> usize { EVENTS.lock().push("wait"); 0 }
    unsafe extern "C" fn lookup(_: *const u8) -> *mut u8 { EVENTS.lock().push("lookup"); NODE }
    unsafe extern "C" fn release(_: *mut u8) -> *mut u8 { EVENTS.lock().push("release"); core::ptr::null_mut() }
    unsafe extern "C" fn signal(_: usize) -> usize { EVENTS.lock().push("signal"); 0 }
    unsafe extern "C" fn error(error: u32) -> u32 { EVENTS.lock().push(if error == 0 { "error0" } else { "error2" }); u32::MAX }

    unsafe fn install() { HOST_OPS = HostOps { drive_index, wait, lookup, release, signal, error }; }
    fn reset() { EVENTS.lock().clear(); unsafe { DRIVE_INDEX = 0; NODE = core::ptr::null_mut(); install(); } }

    #[test]
    fn reads_header_attribute_and_releases_node() {
        let _guard = OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::PATH_ATTRIBUTES, 0x1000) else { return };
        reset();
        unsafe {
            slab.add(4).cast::<u32>().write(slab.add(0x100) as usize as u32);
            slab.add(0x10b).write(0xa5);
            NODE = slab;
            let mut attributes = 0;
            assert_eq!(read_path_attributes(core::ptr::null(), &mut attributes), 1);
            assert_eq!(attributes, 0xa5);
        }
        assert_eq!(*EVENTS.lock(), ["index", "wait", "lookup", "release", "signal", "error0"]);
    }

    #[test]
    fn missing_node_unlocks_and_reports_error_two() {
        let _guard = OPS_LOCK.lock();
        reset();
        unsafe { assert_eq!(read_path_attributes(core::ptr::null(), core::ptr::null_mut()), 0); }
        assert_eq!(*EVENTS.lock(), ["index", "wait", "lookup", "signal", "error2"]);
    }

    #[test]
    fn invalid_drive_returns_without_side_effects() {
        let _guard = OPS_LOCK.lock();
        reset();
        unsafe {
            DRIVE_INDEX = -1;
            assert_eq!(read_path_attributes(core::ptr::null(), core::ptr::null_mut()), 0);
        }
        assert_eq!(*EVENTS.lock(), ["index"]);
    }
}
