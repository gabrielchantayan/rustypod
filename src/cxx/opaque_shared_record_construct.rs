//! Construction of an opaque record containing a shared-handle subobject.
//!
//! ## Original: `FUN_082a7dac` @ 0x082a7dac (96 bytes)
//!
//! Raw `osos.dec` establishes the exact extent from the prologue at
//! `0x082a7dac` through `pop {r4,r5,r6,pc}` at `0x082a7e08`; the word at
//! `0x082a7e0c` is its literal pool and the next separately entered function
//! begins at `0x082a7e10`. Decoding every aligned ARM branch word finds five
//! inbound plain `bl` calls (0x081cdbf8, 0x081cdc60, 0x081e0328, 0x081e03c4,
//! and 0x081e0460) and zero predicated `bl` calls.
//!
//! It copies the fixed descriptor record's vtable into caller storage,
//! constructs a shared-handle subobject at +0x3c, constructs an opaque base,
//! copies the source vtable's indexed payload and +0x24 word, then constructs
//! the final member at +0x0c. `FUN_083d801c` and `FUN_083dace0` have no
//! verified semantic identity, so target builds call their verified retail
//! addresses and host builds use ABI seams. No deliberate deviations.

use crate::cxx::vtable_shared_handle_construct::{vtable_shared_handle_construct, VtableSharedHandle};

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const DEFAULT_SOURCE: *const u32 = 0x089a_8904 as *const u32;
const RETAIL_BASE_CONSTRUCT: usize = 0x083d_801c;
const RETAIL_MEMBER_CONSTRUCT: usize = 0x083d_ace0;

pub type OpaqueSharedRecordBaseConstruct = unsafe extern "C" fn(*mut u32, *const u32, *mut u32) -> *mut u32;
pub type OpaqueSharedRecordMemberConstruct = unsafe extern "C" fn(*mut u32, u32, u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn source_record() -> *const u32 { DEFAULT_SOURCE }

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_SHARED_RECORD_SOURCE: *const u32 = core::ptr::null();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn source_record() -> *const u32 {
    core::ptr::read_volatile(addr_of!(OPAQUE_SHARED_RECORD_SOURCE))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_base(storage: *mut u32, source: *const u32, embedded: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueSharedRecordBaseConstruct>(RETAIL_BASE_CONSTRUCT)(storage, source, embedded)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(storage: *mut u32, _source: *const u32, _embedded: *mut u32) -> *mut u32 { storage }

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_SHARED_RECORD_BASE_CONSTRUCT: OpaqueSharedRecordBaseConstruct = missing_base_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_base(storage: *mut u32, source: *const u32, embedded: *mut u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(OPAQUE_SHARED_RECORD_BASE_CONSTRUCT))(storage, source, embedded)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_member(storage: *mut u32, value: u32, flags: u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueSharedRecordMemberConstruct>(RETAIL_MEMBER_CONSTRUCT)(storage, value, flags)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_member_construct(storage: *mut u32, _value: u32, _flags: u32) -> *mut u32 { storage }

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_SHARED_RECORD_MEMBER_CONSTRUCT: OpaqueSharedRecordMemberConstruct = missing_member_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_member(storage: *mut u32, value: u32, flags: u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(OPAQUE_SHARED_RECORD_MEMBER_CONSTRUCT))(storage, value, flags)
}

/// Constructs the fixed-source opaque record in `storage` and returns the
/// containing address returned by its final member constructor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_shared_record_construct(
    storage: *mut u32,
    value: u32,
    flags: u32,
) -> *mut u32 {
    let source = source_record();
    let vtable = source.read();
    storage.write(vtable);
    let payload_offset = (vtable as *const u32).sub(3).read() as usize;
    storage.add(payload_offset).write(source.add(8).read());
    storage.add(2).write(source.add(9).read());
    vtable_shared_handle_construct(storage.add(15).cast::<VtableSharedHandle>());
    let record = construct_base(storage, source.add(1), storage.add(3));
    construct_member(record.add(3), value, flags).sub(3)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::shared_handle_initialize::{SHARED_HANDLE_GLOBAL, SHARED_HANDLE_INITIALIZE_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const WORDS: usize = 0x400;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::OPAQUE_SHARED_RECORD_CONSTRUCT, WORDS * 4).map(|p| p as usize));
    static LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_ARGS: (*mut u32, *const u32, *mut u32) = (core::ptr::null_mut(), core::ptr::null(), core::ptr::null_mut());
    static mut MEMBER_ARGS: (*mut u32, u32, u32) = (core::ptr::null_mut(), 0, 0);
    static mut BASE_RESULT_OFFSET: usize = 0;

    unsafe extern "C" fn base(storage: *mut u32, source: *const u32, embedded: *mut u32) -> *mut u32 {
        BASE_ARGS = (storage, source, embedded); storage.add(BASE_RESULT_OFFSET)
    }
    unsafe extern "C" fn member(storage: *mut u32, value: u32, flags: u32) -> *mut u32 {
        MEMBER_ARGS = (storage, value, flags); storage
    }
    struct Reset { _lock: MutexGuard<'static, ()>, source: *const u32, base: OpaqueSharedRecordBaseConstruct, member: OpaqueSharedRecordMemberConstruct, shared: u32, base_result_offset: usize }
    impl Drop for Reset { fn drop(&mut self) { unsafe { OPAQUE_SHARED_RECORD_SOURCE = self.source; OPAQUE_SHARED_RECORD_BASE_CONSTRUCT = self.base; OPAQUE_SHARED_RECORD_MEMBER_CONSTRUCT = self.member; SHARED_HANDLE_GLOBAL = self.shared; BASE_RESULT_OFFSET = self.base_result_offset; } } }
    fn reset() -> Reset {
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { let reset = Reset { _lock: lock, source: OPAQUE_SHARED_RECORD_SOURCE, base: OPAQUE_SHARED_RECORD_BASE_CONSTRUCT, member: OPAQUE_SHARED_RECORD_MEMBER_CONSTRUCT, shared: SHARED_HANDLE_GLOBAL, base_result_offset: BASE_RESULT_OFFSET }; OPAQUE_SHARED_RECORD_BASE_CONSTRUCT = base; OPAQUE_SHARED_RECORD_MEMBER_CONSTRUCT = member; BASE_RESULT_OFFSET = 0; BASE_ARGS = (core::ptr::null_mut(), core::ptr::null(), core::ptr::null_mut()); MEMBER_ARGS = (core::ptr::null_mut(), 0, 0); reset }
    }

    #[test]
    fn copies_indexed_payload_and_forwards_member_arguments() {
        let _shared = SHARED_HANDLE_INITIALIZE_TEST_LOCK.lock();
        let _reset = reset();
        let Some(fixture) = *FIXTURE else { assert!(note_missing_u32_fixture("cxx/opaque_shared_record_construct")); return; };
        unsafe {
            let words = fixture as *mut u32; core::ptr::write_bytes(words.cast::<u8>(), 0xa5, WORDS * 4);
            let vtable = words.add(16); vtable.sub(3).write(7);
            let source = words.add(64); source.write(vtable as usize as u32); source.add(8).write(0x1122_3344); source.add(9).write(0x5566_7788);
            let shared = words.add(96); shared.add(7).write(u32::MAX); SHARED_HANDLE_GLOBAL = shared as usize as u32; OPAQUE_SHARED_RECORD_SOURCE = source;
            let storage = words.add(160); let result = opaque_shared_record_construct(storage, 0xdead_beef, 0x21);
            assert_eq!(result, storage); assert_eq!(*storage, *source); assert_eq!(*storage.add(7), 0x1122_3344); assert_eq!(*storage.add(2), 0x5566_7788);
            assert_eq!(BASE_ARGS, (storage, source.add(1).cast_const(), storage.add(3))); assert_eq!(MEMBER_ARGS, (storage.add(3), 0xdead_beef, 0x21));
            assert_eq!(*storage.add(15), 0x089a_8b04); assert_eq!(*shared.add(7), 0);
        }
    }
    #[test]
    fn rebases_the_final_member_result() {
        let _shared = SHARED_HANDLE_INITIALIZE_TEST_LOCK.lock();
        let _reset = reset();
        let Some(fixture) = *FIXTURE else { assert!(note_missing_u32_fixture("cxx/opaque_shared_record_construct result")); return; };
        unsafe {
            let words = fixture as *mut u32; core::ptr::write_bytes(words.cast::<u8>(), 0, WORDS * 4);
            let vtable = words.add(16); vtable.sub(3).write(0);
            let source = words.add(64); source.write(vtable as usize as u32);
            let shared = words.add(96); SHARED_HANDLE_GLOBAL = shared as usize as u32; OPAQUE_SHARED_RECORD_SOURCE = source; BASE_RESULT_OFFSET = 4;
            let storage = words.add(160);
            assert_eq!(opaque_shared_record_construct(storage, 0, 0), storage.add(4));
            assert_eq!(MEMBER_ARGS.0, storage.add(7));
        }
    }
}

