//! XML/plist file loader — FUN_0825c1d0 @ 0x0825c1d0.
//! True extent: 148 bytes (140 code, 8 literals), next entry 0x0825c264.
//! Raw A32 census: six outbound plain BLs, two inbound plain BLs
//! (0x0815a86c, 0x081c8308), zero predicated BLs in either direction.
//! Acquire gateway payload 45, construct a 72-byte file reader with mode 1
//! and buffer size 0x8000, parse into the caller's plist node, map any nonzero
//! parser result to 34, destroy the reader and its string base, then release
//! the gateway with timeout 1000. Cleanup occurs on both result paths.
//! Deviations: constructor 0x0825c984 and parser 0x0825c378 remain verified
//! retail boundaries, not reimplemented dependencies. An ops table supports
//! host execution without firmware vtables; target defaults reuse ported
//! gateways and destructors. Opaque reader storage retains target word layout
//! on hosts; host boundary implementations must respect this 72-byte extent.

use core::{mem::MaybeUninit, ptr};
use crate::cxx::string_object::StringObject;

pub type ReaderConstruct = unsafe extern "C" fn(*mut u32, *const StringObject, u32, u32, u32) -> *mut u32;
pub type ParseReader = unsafe extern "C" fn(*mut u8, *mut u32) -> u32;

#[derive(Clone, Copy)]
pub struct PlistFileLoadOps {
    pub acquire: unsafe extern "C" fn(usize, usize),
    pub construct: ReaderConstruct,
    pub parse: ParseReader,
    pub destroy_store: unsafe extern "C" fn(*mut u8) -> *mut u8,
    pub destroy_string: unsafe extern "C" fn(*mut StringObject) -> *mut StringObject,
    pub release: unsafe extern "C" fn(usize, usize),
}

unsafe extern "C" fn construct_reader(storage: *mut u32, path: *const StringObject, mode: u32, option: u32, capacity: u32) -> *mut u32 {
    #[cfg(target_os = "none")]
    { let call: ReaderConstruct = core::mem::transmute(0x0825_c984usize); call(storage, path, mode, option, capacity) }
    #[cfg(not(target_os = "none"))]
    { let _ = (storage, path, mode, option, capacity); panic!("plist reader construction requires retailOS or installed host ops") }
}
unsafe extern "C" fn parse_reader(node: *mut u8, reader: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    { let call: ParseReader = core::mem::transmute(0x0825_c378usize); call(node, reader) }
    #[cfg(not(target_os = "none"))]
    { let _ = (node, reader); panic!("plist parsing requires retailOS or installed host ops") }
}

pub static mut PLIST_FILE_LOAD_OPS: PlistFileLoadOps = PlistFileLoadOps {
    acquire: crate::kernel::gateway_request_blocking::gateway_request_blocking,
    construct: construct_reader,
    parse: parse_reader,
    destroy_store: crate::app::vtable_set::vtable_file_store_destruct,
    destroy_string: crate::cxx::string_object::string_object_destroy_veneer,
    release: crate::kernel::gateway_request::gateway_request_timed,
};

/// Load `node` from `path`, returning zero or retail error 34.
///
/// # Safety
/// Node and path must satisfy the retail parser/constructor contracts. Installed
/// host ops must initialize and destroy the target-layout reader, and may not
/// retain its stack storage. Mutating the ops table requires external exclusion.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plist_file_load(node: *mut u8, path: *const StringObject, option: u32) -> u32 {
    load_with_ops(node, path, option, ptr::read_volatile(ptr::addr_of!(PLIST_FILE_LOAD_OPS)))
}

unsafe fn load_with_ops(node: *mut u8, path: *const StringObject, option: u32, ops: PlistFileLoadOps) -> u32 {
    (ops.acquire)(45, 0);
    let mut storage = MaybeUninit::<[u32; 18]>::uninit();
    let reader = storage.as_mut_ptr().cast::<u32>();
    (ops.construct)(reader, path, 1, option, 0x8000);
    let status = (ops.parse)(node, reader);
    reader.write(0x089a_8064);
    let store = (ops.destroy_store)(reader.add(5).cast());
    store.wrapping_sub(20).cast::<u32>().write(0x089a_8080);
    (ops.destroy_string)(store.wrapping_sub(8).cast());
    (ops.release)(45, 1000);
    if status == 0 { 0 } else { 34 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static STATE: Mutex<(u32, u32, usize)> = Mutex::new((0, 0, 0));
    unsafe extern "C" fn acquire(_: usize, _: usize) { STATE.lock().0 = 1; }
    unsafe extern "C" fn construct(reader: *mut u32, _: *const StringObject, _: u32, _: u32, _: u32) -> *mut u32 {
        assert_eq!(STATE.lock().0, 1);
        // Model two owned resources, at the string and file-store boundaries.
        ptr::write_bytes(reader, 0, 18);
        reader.add(4).write(1);
        reader.add(17).write(1);
        STATE.lock().0 = 2;
        reader
    }
    unsafe extern "C" fn parse(node: *mut u8, reader: *mut u32) -> u32 {
        assert_eq!(reader.add(4).read(), 1);
        assert_eq!(reader.add(17).read(), 1);
        let mut state = STATE.lock();
        assert_eq!(state.0, 2);
        state.0 = 3;
        node.cast::<u32>().write(0x1234_5678);
        state.1
    }
    unsafe extern "C" fn destroy_store(store: *mut u8) -> *mut u8 {
        let reader = store.sub(20).cast::<u32>();
        assert_eq!(reader.read(), 0x089a_8064);
        assert_eq!(reader.add(17).read(), 1);
        reader.add(17).write(0);
        let mut state = STATE.lock();
        assert_eq!(state.0, 3);
        state.0 = 4;
        state.2 = reader as usize;
        store
    }
    unsafe extern "C" fn destroy_string(string: *mut StringObject) -> *mut StringObject {
        let reader = string.cast::<u8>().sub(12).cast::<u32>();
        assert_eq!(reader.read(), 0x089a_8080);
        assert_eq!(reader.add(17).read(), 0);
        assert_eq!(reader.add(4).read(), 1);
        reader.add(4).write(0);
        let mut state = STATE.lock();
        assert_eq!(reader as usize, state.2);
        assert_eq!(state.0, 4);
        state.0 = 5;
        string
    }
    unsafe extern "C" fn release(_: usize, _: usize) {
        let mut state = STATE.lock();
        assert_eq!(state.0, 5);
        let reader = state.2 as *const u32;
        assert_eq!(reader.add(4).read(), 0);
        assert_eq!(reader.add(17).read(), 0);
        state.0 = 6;
    }
    #[test]
    fn success_and_every_nonzero_error_release_both_resources() {
        let ops = PlistFileLoadOps { acquire, construct, parse, destroy_store, destroy_string, release };
        for status in [0, 1, 34, 0x8000_0000, u32::MAX] {
            *STATE.lock() = (0, status, 0);
            let mut node = 0u32;
            let result = unsafe { load_with_ops(ptr::addr_of_mut!(node).cast(), ptr::null(), u32::MAX, ops) };
            assert_eq!(result, if status == 0 { 0 } else { 34 });
            assert_eq!(node, 0x1234_5678);
            assert_eq!(STATE.lock().0, 6);
        }
    }
}
