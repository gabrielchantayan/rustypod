//! Resource path lookup and UTF-16 materialization.
//!
//! `resource_path_lookup` — original: `FUN_0813e858` @ **0x0813e858**
//! (208 bytes; 8 unconditional plain `bl` instructions in the body, 0
//! predicated `bl`). Raw `osos.dec` establishes the extent through the final
//! branch at 0x0813e924; the next function starts at 0x0813e928.
//!
//! The routine constructs a temporary PathObject, finds a direct-key resource
//! record through `context + 0x40`, selects its child by `selector`, exports
//! that child's counted byte string into a temporary length-prefixed UTF-16
//! buffer, and assigns it to `out_path`. On success it returns one and copies
//! record words +0x18/+0x1c to the two output slots; every other path returns
//! zero. The temporary is destroyed on all paths.
//!
//! Deliberate deviations: the three still-unported resource helpers remain
//! fixed-address target calls. Host tests replace those boundaries and the
//! already-ported path/string operations with native callbacks.

use crate::app::path_object_construct::path_object_default_construct;
use crate::cxx::string_export_counted_utf16::string_export_counted_utf16;
use crate::cxx::string_object::{string_object_assign_utf16, string_object_destroy, StringObject};
type AssignUtf16 = unsafe extern "C" fn(*mut StringObject, *const u16, i32);
type DirectLookup = unsafe extern "C" fn(*mut u32, u32) -> *mut u32;
type ChildLookup = unsafe extern "C" fn(*mut u32, u32) -> *mut u8;
type PathBuild = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> i32;
type ExportPath = unsafe extern "C" fn(*const u8, u32, *mut u16) -> i32;
type PathConstruct = unsafe extern "C" fn(*mut StringObject) -> *mut StringObject;
type PathDestroy = unsafe extern "C" fn(*mut StringObject) -> *mut StringObject;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn direct_lookup(index: *mut u32, key: u32) -> *mut u32 {
    let function: DirectLookup = core::mem::transmute(0x0805_0418usize);
    function(index, key)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn child_lookup(record: *mut u32, selector: u32) -> *mut u8 {
    let function: ChildLookup = core::mem::transmute(0x0805_0708usize);
    function(record, selector)
}
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn build_path(entry: *mut u8, output: *mut u8) -> i32 {
    let function: PathBuild = core::mem::transmute(0x0805_23bcusize);
    function(entry, output, 0)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn export_path(source: *const u8, destination: *mut u16) -> i32 {
    string_export_counted_utf16(source, 0, destination)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn assign_path(destination: *mut StringObject, source: *const u16, length: i32) {
    string_object_assign_utf16(destination, source, length)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_path(path: *mut StringObject) -> *mut StringObject { path_object_default_construct(path) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_path(path: *mut StringObject) -> *mut StringObject { string_object_destroy(path) }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps { direct: DirectLookup, child: ChildLookup, build: PathBuild, export: ExportPath, assign: AssignUtf16, construct: PathConstruct, destroy: PathDestroy }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_direct(_: *mut u32, _: u32) -> *mut u32 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_child(_: *mut u32, _: u32) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_build(_: *mut u8, _: *mut u8, _: u32) -> i32 { -1 }
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps { direct: unavailable_direct, child: unavailable_child, build: unavailable_build, export: string_export_counted_utf16, assign: string_object_assign_utf16, construct: path_object_default_construct, destroy: string_object_destroy };
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn direct_lookup(index: *mut u32, key: u32) -> *mut u32 { (HOST_OPS.direct)(index, key) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn child_lookup(record: *mut u32, selector: u32) -> *mut u8 { (HOST_OPS.child)(record, selector) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn build_path(entry: *mut u8, output: *mut u8) -> i32 { (HOST_OPS.build)(entry, output, 0) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn export_path(source: *const u8, destination: *mut u16) -> i32 { (HOST_OPS.export)(source, 0, destination) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn assign_path(destination: *mut StringObject, source: *const u16, length: i32) { (HOST_OPS.assign)(destination, source, length) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_path(path: *mut StringObject) -> *mut StringObject { (HOST_OPS.construct)(path) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_path(path: *mut StringObject) -> *mut StringObject { (HOST_OPS.destroy)(path) }

/// Looks up and materializes a selected resource path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resource_path_lookup(context: *mut u32, key: u32, selector: u32, out_path: *mut StringObject, out_a: *mut u32, out_b: *mut u32) -> u32 {
    let mut temporary = core::mem::MaybeUninit::<StringObject>::uninit();
    construct_path(temporary.as_mut_ptr());
    let record = direct_lookup(context.add(16), key);
    let success = if record.is_null() {
        false
    } else {
        let path = child_lookup(record, selector);
        if path.is_null() {
            false
        } else {
            let mut counted_path = [0u8; 260];
            let mut utf16 = [0u16; 130];
            if build_path(path, counted_path.as_mut_ptr()) != 0 || export_path(counted_path.as_ptr(), utf16.as_mut_ptr()) != 0 {
                false
            } else {
                assign_path(out_path, utf16.as_ptr().add(1), utf16[0] as i32);
                out_a.write_volatile(record.add(6).read_volatile());
                out_b.write_volatile(record.add(7).read_volatile());
                true
            }
        }
    };
    destroy_path(temporary.as_mut_ptr());
    success as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RECORD: *mut u32 = core::ptr::null_mut();
    static mut PATH: *mut u8 = core::ptr::null_mut();
    static mut DIRECT_ARGS: (usize, u32) = (0, 0);
    static mut CHILD_ARGS: (usize, u32) = (0, 0);
    static mut EXPORT_STATUS: i32 = 0;
    static mut CONSTRUCTS: u32 = 0;
    static mut DESTROYS: u32 = 0;
    unsafe extern "C" fn direct(index: *mut u32, key: u32) -> *mut u32 { DIRECT_ARGS = (index as usize, key); RECORD }
    unsafe extern "C" fn child(record: *mut u32, selector: u32) -> *mut u8 { CHILD_ARGS = (record as usize, selector); PATH }
    unsafe extern "C" fn build(_: *mut u8, _: *mut u8, _: u32) -> i32 { 0 }
    unsafe extern "C" fn export(_: *const u8, _: u32, destination: *mut u16) -> i32 { destination.write(3); EXPORT_STATUS }
    unsafe extern "C" fn assign(_: *mut StringObject, _: *const u16, _: i32) {}
    unsafe extern "C" fn construct(path: *mut StringObject) -> *mut StringObject { CONSTRUCTS += 1; path }
    unsafe extern "C" fn destroy(path: *mut StringObject) -> *mut StringObject { DESTROYS += 1; path }
    struct Guard(HostOps);
    impl Drop for Guard { fn drop(&mut self) { unsafe { HOST_OPS = self.0; } } }
    fn install() -> Guard { let old = unsafe { HOST_OPS }; unsafe { HOST_OPS = HostOps { direct, child, build, export, assign, construct, destroy }; RECORD = core::ptr::null_mut(); PATH = core::ptr::null_mut(); EXPORT_STATUS = 0; CONSTRUCTS = 0; DESTROYS = 0; DIRECT_ARGS = (0, 0); CHILD_ARGS = (0, 0); } Guard(old) }
    #[test]
    fn success_selects_path_and_copies_record_words() {
        let _lock = LOCK.lock(); let _guard = install();
        let mut context = [0u32; 20]; let mut record = [0u32; 8]; let mut path = [0u8; 4]; let mut output = StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() }; let mut a = 0; let mut b = 0;
        record[6] = 0x1122_3344; record[7] = 0x5566_7788;
        unsafe { RECORD = record.as_mut_ptr(); PATH = path.as_mut_ptr(); assert_eq!(resource_path_lookup(context.as_mut_ptr(), 7, 9, &mut output, &mut a, &mut b), 1); assert_eq!(DIRECT_ARGS, (context.as_mut_ptr().add(16) as usize, 7)); assert_eq!(CHILD_ARGS, (record.as_mut_ptr() as usize, 9)); assert_eq!((a, b), (record[6], record[7])); assert_eq!((CONSTRUCTS, DESTROYS), (1, 1)); }
    }
    #[test]
    fn failed_export_preserves_outputs_and_still_destroys_temporary() {
        let _lock = LOCK.lock(); let _guard = install();
        let mut context = [0u32; 20]; let mut record = [0u32; 8]; let mut path = [0u8; 4]; let mut output = StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() }; let mut a = 1; let mut b = 2;
        unsafe { RECORD = record.as_mut_ptr(); PATH = path.as_mut_ptr(); EXPORT_STATUS = -1; assert_eq!(resource_path_lookup(context.as_mut_ptr(), 0, 0, &mut output, &mut a, &mut b), 0); assert_eq!((a, b), (1, 2)); assert_eq!((CONSTRUCTS, DESTROYS), (1, 1)); }
    }
}
