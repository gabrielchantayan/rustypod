//! parser_name_record_insert — retailOS `FUN_080734d8` @ `0x080734d8` (156 bytes,
//! `0x080734d8..0x08073573`; the next independently linked function starts at
//! `0x08073574`). Raw ARM has eight unconditional `bl` instructions and one
//! predicated `blne`; decoding the complete image finds three inbound direct
//! calls, two plain `bl` and one predicated `blne`.
//!
//! Creates the zero-argument ATA handle, allocates a 12-byte `{name, 0, handle}`
//! record, duplicates `name` including its NUL, and inserts the record into the
//! lhash at `parser + 0x08`. Any allocation failure destroys the handle and,
//! when necessary, the record, then returns NULL. Deliberate deviations: the
//! stock `__rt_memcpy` call is a volatile byte copy, preventing LLVM from
//! replacing it with an unavailable runtime builtin; the direct lhash insertion
//! and existing allocator/handle seams preserve the target's observable calls.

use core::ffi::c_void;

use crate::crypto::obj_dat::{lh_insert, Lhash};
use crate::drivers::ata_cmd::{ata_call_with_zero, traced_alloc, traced_free};
use crate::libc::strlen::strlen;

#[repr(C)]
struct ParserNameRecord {
    name: *mut u8,
    reserved: u32,
    handle: *mut usize,
}

/// Allocates and inserts a parser name record.
///
/// # Safety
///
/// `parser` must have a valid `*mut Lhash` word at offset 8; `name` must be a
/// valid NUL-terminated byte string. The installed heap, ATA-handle, and lhash
/// services must accept the resulting objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parser_name_record_insert(
    parser: *mut u8,
    name: *const u8,
) -> *mut ParserNameRecord {
    let handle = ata_call_with_zero();
    if handle.is_null() {
        return core::ptr::null_mut();
    }

    let record = traced_alloc(12, 0, 0).cast::<ParserNameRecord>();
    if record.is_null() {
        crate::cxx::object_flags::namespace_provider_destroy(handle.cast());
        return core::ptr::null_mut();
    }

    let name_len = strlen(name);
    let copy = traced_alloc(name_len.wrapping_add(1) as i32, 0, 0);
    record.write(ParserNameRecord { name: copy, reserved: 0, handle: handle.cast() });
    if copy.is_null() {
        crate::cxx::object_flags::namespace_provider_destroy(handle.cast());
        traced_free(record.cast());
        return core::ptr::null_mut();
    }

    let mut dst = copy;
    let mut src = name;
    for _ in 0..=name_len {
        dst.write_volatile(src.read_volatile());
        dst = dst.add(1);
        src = src.add(1);
    }

    let table = parser.add(8).cast::<*mut Lhash>().read();
    lh_insert(table, record.cast::<c_void>());
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::obj_dat::{LhashNode, LhashGetrn, LHASH_GETRN, LHASH_TEST_LOCK};
    use crate::drivers::ata_cmd::{AtaHandleHooks, TracedAllocHooks, ATA_HANDLE_HOOKS, TRACED_ALLOC_HOOKS};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut HANDLE: [u32; 5] = [0; 5];
    static mut RECORD: ParserNameRecord = ParserNameRecord { name: core::ptr::null_mut(), reserved: 0, handle: core::ptr::null_mut() };
    static mut TEXT: [u8; 32] = [0; 32];
    static mut NODE: LhashNode = LhashNode { data: core::ptr::null_mut(), next: core::ptr::null_mut() };
    static mut BUCKET: *mut LhashNode = core::ptr::null_mut();
    static mut ALLOC_CALLS: [i32; 4] = [0; 4];
    static mut FAIL_SIZE: i32 = -1;

    unsafe extern "C" fn make_handle(_param: u32) -> *mut u32 { core::ptr::addr_of_mut!(HANDLE).cast() }
    unsafe extern "C" fn allocate(size: i32, _tag1: u32, _tag2: u32) -> *mut u8 {
        let calls = core::ptr::addr_of_mut!(ALLOC_CALLS);
        let index = (*calls)[0] as usize;
        (*calls)[0] += 1;
        if size == FAIL_SIZE { return core::ptr::null_mut(); }
        (*calls)[index + 1] = size;
        match index {
            0 => core::ptr::addr_of_mut!(RECORD).cast(),
            1 => core::ptr::addr_of_mut!(TEXT).cast(),
            _ => core::ptr::addr_of_mut!(NODE).cast(),
        }
    }
    unsafe extern "C" fn bucket_for_insert(_table: *mut Lhash, _key: *const c_void, _hash: *mut u32) -> *mut *mut LhashNode {
        core::ptr::addr_of_mut!(BUCKET)
    }

    struct Reset { alloc: TracedAllocHooks, handle: AtaHandleHooks, getrn: LhashGetrn }
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { TRACED_ALLOC_HOOKS = self.alloc; ATA_HANDLE_HOOKS = self.handle; LHASH_GETRN = self.getrn; } }
    }

    #[test]
    fn duplicates_including_nul_and_inserts_the_record() {
        let _test = TEST_LOCK.lock();
        let _alloc = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _lhash = LHASH_TEST_LOCK.lock();
        let reset = unsafe { Reset { alloc: TRACED_ALLOC_HOOKS, handle: ATA_HANDLE_HOOKS, getrn: LHASH_GETRN } };
        unsafe {
            ALLOC_CALLS = [0; 4]; FAIL_SIZE = -1; BUCKET = core::ptr::null_mut();
            TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: allocate, trace: None };
            ATA_HANDLE_HOOKS = AtaHandleHooks { create: make_handle };
            LHASH_GETRN = bucket_for_insert;
            let mut table = Lhash::empty(); table.num_nodes = 1; table.up_load = 256;
            let mut parser = [0usize; 2]; parser[1] = core::ptr::addr_of_mut!(table) as usize;
            let record = parser_name_record_insert(parser.as_mut_ptr().cast(), b"edge\0".as_ptr());
            assert_eq!((*record).name, core::ptr::addr_of_mut!(TEXT).cast());
            assert_eq!((*record).reserved, 0);
            assert_eq!((*record).handle, core::ptr::addr_of_mut!(HANDLE).cast::<usize>());
            assert_eq!(&TEXT[..5], b"edge\0");
            assert_eq!(ALLOC_CALLS, [3, 12, 5, 12]);
            assert_eq!(BUCKET, core::ptr::addr_of_mut!(NODE));
            assert_eq!(NODE.data, record.cast());
            ALLOC_CALLS = [0; 4];
            FAIL_SIZE = 5;
            assert!(parser_name_record_insert(parser.as_mut_ptr().cast(), b"edge\0".as_ptr()).is_null());
            assert_eq!(ALLOC_CALLS, [2, 12, 0, 0]);
        }
        drop(reset);
    }
}
