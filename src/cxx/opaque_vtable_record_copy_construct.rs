//! Copy-construction of an opaque vtable-bearing record.
//!
//! ## Original: `FUN_082a7e10` @ 0x082a7e10
//!
//! Raw `osos.dec` establishes a 92-byte instruction extent,
//! `0x082a7e10..0x082a7e68`; the literal at `0x082a7e6c` belongs to this
//! function and the next independently linked function starts at `0x082a7e70`.
//! Decoding its words finds three plain `bl` calls (`0x083dadd4`,
//! `0x082a77b0`, and conditionally `0x082a94d0`) and zero predicated `bl`
//! calls. It selects either the supplied source record or a fixed default,
//! copies its vtable, vtable-indexed word, and +0x24 word, then constructs an
//! embedded base and copies its trailing opaque member. A nonzero selector
//! destroys the member at the returned record's +0x3c word before returning
//! its containing address.
//!
//! Deliberate deviations: `FUN_083dadd4` and `FUN_082a77b0` have no verified
//! semantic identities, so they remain exact-address ABI seams. The final
//! cleanup calls the existing `shared_handle_owner_destroy` port rather than
//! resident retailOS on the target.

use crate::cxx::shared_handle_owner_destroy::shared_handle_owner_destroy;

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

#[cfg(not(target_os = "none"))]
pub static mut DEFAULT_OPAQUE_VTABLE_RECORD_SOURCE: *const u32 = core::ptr::null();

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn default_source() -> *const u32 {
    DEFAULT_SOURCE
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn default_source() -> *const u32 {
    core::ptr::read_volatile(addr_of!(DEFAULT_OPAQUE_VTABLE_RECORD_SOURCE))
}

const RETAIL_BASE_CONSTRUCT: usize = 0x083d_add4;
const RETAIL_MEMBER_COPY_CONSTRUCT: usize = 0x082a_77b0;
const DEFAULT_SOURCE: *const u32 = 0x089a_8904 as *const u32;
const MEMBER_DESTROY_OFFSET_WORDS: usize = 15;

pub type OpaqueBaseConstruct = unsafe extern "C" fn(*mut u32) -> *mut u32;
pub type OpaqueMemberCopyConstruct = unsafe extern "C" fn(*mut u32, u32, *const u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_base(storage: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueBaseConstruct>(RETAIL_BASE_CONSTRUCT)(storage)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(storage: *mut u32) -> *mut u32 { storage.add(3) }

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_BASE_CONSTRUCT: OpaqueBaseConstruct = missing_base_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_base(storage: *mut u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(OPAQUE_BASE_CONSTRUCT))(storage)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn copy_member(storage: *mut u32, source: *const u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueMemberCopyConstruct>(RETAIL_MEMBER_COPY_CONSTRUCT)(storage, 0, source)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_member_copy_construct(storage: *mut u32, _zero: u32, _source: *const u32) -> *mut u32 { storage }

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_MEMBER_COPY_CONSTRUCT: OpaqueMemberCopyConstruct = missing_member_copy_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn copy_member(storage: *mut u32, source: *const u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(OPAQUE_MEMBER_COPY_CONSTRUCT))(storage, 0, source)
}

/// Copies `source` into caller-owned `storage` and returns the constructed
/// record. Both pointers must be valid target-width word arrays; `source` must
/// contain words zero through nine, and its word zero must point at readable
/// vtable storage through offset -12.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_record_copy_construct(
    storage: *mut u32,
    use_default_source: u32,
    source: *const u32,
) -> *mut u32 {
    let source = if use_default_source != 0 { default_source() } else { source };
    let vtable = source.read();
    storage.write(vtable);
    storage.add((vtable as *const u32).offset(-3).read() as usize).write(source.add(8).read());
    storage.add(2).write(source.add(9).read());

    let base = construct_base(storage.add(3));
    let record = copy_member(base.sub(3), source.add(1));
    if use_default_source != 0 {
        shared_handle_owner_destroy(record.add(MEMBER_DESTROY_OFFSET_WORDS))
            .sub(MEMBER_DESTROY_OFFSET_WORDS)
    } else {
        record
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::shared_handle_owner_destroy::{
        CallbackDispatch, SharedHandleRelease, CALLBACK_DISPATCH, SHARED_HANDLE_RELEASE,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_ARGUMENT: *mut u32 = core::ptr::null_mut();
    static mut MEMBER_ARGUMENT: (*mut u32, u32, *const u32) =
        (core::ptr::null_mut(), 1, core::ptr::null());
    static mut DESTROY_ARGUMENT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn base_construct(storage: *mut u32) -> *mut u32 {
        BASE_ARGUMENT = storage;
        storage
    }
    unsafe extern "C" fn member_copy(storage: *mut u32, zero: u32, source: *const u32) -> *mut u32 {
        MEMBER_ARGUMENT = (storage, zero, source);
        storage
    }
    unsafe extern "C" fn callback_dispatch(owner: *mut u32, _event: u32, _context: u32) {
        DESTROY_ARGUMENT = owner;
    }
    unsafe extern "C" fn release(handle: *mut u32) -> *mut u32 { handle }

    struct Reset {
        _lock: MutexGuard<'static, ()>,
        base: OpaqueBaseConstruct,
        member: OpaqueMemberCopyConstruct,
        callback: CallbackDispatch,
        release: SharedHandleRelease,
        default_source: *const u32,
    }
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                OPAQUE_BASE_CONSTRUCT = self.base;
                OPAQUE_MEMBER_COPY_CONSTRUCT = self.member;
                CALLBACK_DISPATCH = self.callback;
                SHARED_HANDLE_RELEASE = self.release;
                DEFAULT_OPAQUE_VTABLE_RECORD_SOURCE = self.default_source;
            }
        }
    }
    fn reset() -> Reset {
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let reset = Reset {
                _lock: lock,
                base: OPAQUE_BASE_CONSTRUCT,
                member: OPAQUE_MEMBER_COPY_CONSTRUCT,
                callback: CALLBACK_DISPATCH,
                release: SHARED_HANDLE_RELEASE,
                default_source: DEFAULT_OPAQUE_VTABLE_RECORD_SOURCE,
            };
            OPAQUE_BASE_CONSTRUCT = base_construct;
            OPAQUE_MEMBER_COPY_CONSTRUCT = member_copy;
            CALLBACK_DISPATCH = callback_dispatch;
            SHARED_HANDLE_RELEASE = release;
            BASE_ARGUMENT = core::ptr::null_mut();
            MEMBER_ARGUMENT = (core::ptr::null_mut(), 1, core::ptr::null());
            DESTROY_ARGUMENT = core::ptr::null_mut();
            reset
        }
    }

    #[test]
    fn copies_supplied_header_and_constructs_member() {
        let _reset = reset();
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_VTABLE_RECORD_COPY_CONSTRUCT, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/opaque_vtable_record_copy_construct"));
            return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let words = slab.cast::<u32>();
            let vtable = words.add(4);
            vtable.write(5); vtable.add(1).write(0); vtable.add(2).write(0);
            let source = words.add(32);
            source.write(vtable.add(3) as usize as u32);
            source.add(8).write(0x1122_3344); source.add(9).write(0x5566_7788);
            let storage = words.add(64);
            let result = opaque_vtable_record_copy_construct(storage, 0, source);
            assert_eq!(result, storage);
            assert_eq!(*storage, *source); assert_eq!(*storage.add(5), 0x1122_3344);
            assert_eq!(*storage.add(2), 0x5566_7788);
            assert_eq!(BASE_ARGUMENT, storage.add(3));
            assert_eq!(MEMBER_ARGUMENT, (storage, 0, source.add(1).cast_const()));
            assert!(DESTROY_ARGUMENT.is_null());
        }
    }

    #[test]
    fn default_source_destroys_member_and_rebases_result() {
        let _reset = reset();
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_VTABLE_RECORD_COPY_CONSTRUCT_DEFAULT, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/opaque_vtable_record_copy_construct default"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let words = slab.cast::<u32>();
            let vtable = words.add(4); vtable.write(3);
            let source = words.add(32); source.write(vtable.add(3) as usize as u32);
            DEFAULT_OPAQUE_VTABLE_RECORD_SOURCE = source;
            let storage = words.add(64);
            assert_eq!(opaque_vtable_record_copy_construct(storage, 1, core::ptr::null()), storage);
            assert_eq!(DESTROY_ARGUMENT, storage.add(15));
            assert_eq!(MEMBER_ARGUMENT.1, 0);
        }
    }
}
