//! `opaque_vtable_record_construct` — retailOS `FUN_082a7e70` @ `0x082a7e70`.
//!
//! ## Original
//!
//! The true instruction extent is 84 bytes (`0x082a7e70..0x082a7ec0`); the
//! literal at `0x082a7ec4` is the default source and the next real function
//! begins at `0x082a7ec8`. Decoding the four-byte-aligned A32 words finds
//! three plain `bl` calls (`0x083dadd4`, `0x082a7868`, and conditionally
//! `0x082a94d0`) and no predicated `bl` calls. It chooses a supplied or fixed
//! source, installs its vtable and vtable-indexed member, constructs the
//! embedded base, then returns the enclosing record. The conditional member
//! cleanup is called with zero, so `FUN_082a7868` returns its input unchanged.
//!
//! Deliberate deviation: Rust expresses that verified zero-selector no-op
//! directly instead of retaining a call to the unported `FUN_082a7868`.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_BASE_CONSTRUCT: usize = 0x083d_add4;
const DEFAULT_SOURCE: *const u32 = 0x089a_897c as *const u32;
const MEMBER_DESTROY_OFFSET_WORDS: usize = 13;

pub type OpaqueBaseConstruct = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_base(storage: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueBaseConstruct>(RETAIL_BASE_CONSTRUCT)(storage)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(storage: *mut u32) -> *mut u32 { storage }

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_VTABLE_RECORD_BASE_CONSTRUCT: OpaqueBaseConstruct = missing_base_construct;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_base(storage: *mut u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(OPAQUE_VTABLE_RECORD_BASE_CONSTRUCT))(storage)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn default_source() -> *const u32 { DEFAULT_SOURCE }

#[cfg(not(target_os = "none"))]
pub static mut DEFAULT_OPAQUE_VTABLE_RECORD_CONSTRUCT_SOURCE: *const u32 = core::ptr::null();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn default_source() -> *const u32 {
    core::ptr::read_volatile(addr_of!(DEFAULT_OPAQUE_VTABLE_RECORD_CONSTRUCT_SOURCE))
}

/// Constructs `storage` from the target-width source layout and returns it.
/// `source` must provide words zero through three; word zero points to readable
/// vtable storage through byte offset minus 12.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_record_construct(
    storage: *mut u32,
    use_default_source: u32,
    source: *const u32,
) -> *mut u32 {
    let source = if use_default_source != 0 { default_source() } else { source };
    let vtable = source.read();
    storage.write(vtable);
    storage.cast::<u8>().add((vtable as *const u32).offset(-3).read() as usize).cast::<u32>().write(source.add(3).read());

    let base = construct_base(storage.add(1));
    let record = base.sub(1);
    if use_default_source != 0 {
        crate::cxx::shared_handle_owner_destroy::shared_handle_owner_destroy(record.add(MEMBER_DESTROY_OFFSET_WORDS))
            .sub(MEMBER_DESTROY_OFFSET_WORDS)
    } else {
        record
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::shared_handle_owner_destroy::{CallbackDispatch, SharedHandleRelease, CALLBACK_DISPATCH, SHARED_HANDLE_RELEASE};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_ARGUMENT: *mut u32 = core::ptr::null_mut();
    static mut DESTROY_ARGUMENT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn base_construct(storage: *mut u32) -> *mut u32 {
        BASE_ARGUMENT = storage;
        storage
    }
    unsafe extern "C" fn callback_dispatch(owner: *mut u32, _event: u32, _context: u32) {
        DESTROY_ARGUMENT = owner;
    }
    unsafe extern "C" fn release(handle: *mut u32) -> *mut u32 { handle }

    struct Reset {
        _lock: MutexGuard<'static, ()>, base: OpaqueBaseConstruct,
        callback: CallbackDispatch, release: SharedHandleRelease, default_source: *const u32,
    }
    impl Drop for Reset {
        fn drop(&mut self) { unsafe {
            OPAQUE_VTABLE_RECORD_BASE_CONSTRUCT = self.base;
            CALLBACK_DISPATCH = self.callback; SHARED_HANDLE_RELEASE = self.release;
            DEFAULT_OPAQUE_VTABLE_RECORD_CONSTRUCT_SOURCE = self.default_source;
        }}
    }
    fn reset() -> Reset {
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let reset = Reset { _lock: lock, base: OPAQUE_VTABLE_RECORD_BASE_CONSTRUCT,
                callback: CALLBACK_DISPATCH, release: SHARED_HANDLE_RELEASE,
                default_source: DEFAULT_OPAQUE_VTABLE_RECORD_CONSTRUCT_SOURCE };
            OPAQUE_VTABLE_RECORD_BASE_CONSTRUCT = base_construct;
            CALLBACK_DISPATCH = callback_dispatch; SHARED_HANDLE_RELEASE = release;
            BASE_ARGUMENT = core::ptr::null_mut(); DESTROY_ARGUMENT = core::ptr::null_mut();
            reset
        }
    }

    #[test]
    fn constructs_supplied_record_at_vtable_selected_byte_offset() {
        let _reset = reset();
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_VTABLE_RECORD_CONSTRUCT, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/opaque_vtable_record_construct")); return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000); let words = slab.cast::<u32>();
            let vtable = words.add(4); vtable.write(24); vtable.add(1).write(0); vtable.add(2).write(0);
            let source = words.add(32); source.write(vtable.add(3) as usize as u32); source.add(3).write(0x1122_3344);
            let storage = words.add(64);
            assert_eq!(opaque_vtable_record_construct(storage, 0, source), storage);
            assert_eq!(*storage, *source); assert_eq!(*storage.add(6), 0x1122_3344);
            assert_eq!(BASE_ARGUMENT, storage.add(1)); assert!(DESTROY_ARGUMENT.is_null());
        }
    }

    #[test]
    fn default_source_destroys_the_embedded_member_and_rebases_result() {
        let _reset = reset();
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_VTABLE_RECORD_CONSTRUCT_DEFAULT, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/opaque_vtable_record_construct default")); return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000); let words = slab.cast::<u32>();
            let vtable = words.add(4); vtable.write(12);
            let source = words.add(32); source.write(vtable.add(3) as usize as u32); source.add(3).write(0x5566_7788);
            DEFAULT_OPAQUE_VTABLE_RECORD_CONSTRUCT_SOURCE = source;
            let storage = words.add(64);
            assert_eq!(opaque_vtable_record_construct(storage, 1, core::ptr::null()), storage);
            assert_eq!(DESTROY_ARGUMENT, storage.add(13)); assert_eq!(*storage.add(3), 0x5566_7788);
        }
    }
}
