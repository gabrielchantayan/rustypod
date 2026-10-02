//! Notes-view initialization — `FUN_0828bcd0` @ `0x0828bcd0`.
//!
//! True extent: 216 bytes to the next function at `0x0828bda8`: 200 code
//! bytes and 16 literal bytes ("Notes", 0x089cffac, 0x089ca674). Full-image
//! aligned A32 decoding finds two inbound plain BLs (0x08117644,
//! 0x0828b394), zero predicated BLs; the body has 12 plain BLs and no
//! predicated BLs. Ghidra's second caller is a spurious interior boundary.
//!
//! Invalidates the embedded path's cached index, assigns "Notes", clears its
//! primary string, selects that path, resets the local byte-source flags,
//! clears the global flag, propagates byte 3 = 1, and snapshots a global word.
//! Registers the resource request only when the two-level handle is empty.
//!
//! Deviations: widened host pointers use named repr(C) fields rather than
//! target byte offsets. Existing StringObject and handle ports are reused.
//! The two unported helpers retain their verified retail addresses on ARM;
//! host callers must supply those boundaries. Global pointers are injectable
//! on hosts; ARM always uses the original global addresses. The host-only
//! path boundary permits fixtures without invoking the device allocator.

use core::ptr;
use crate::app::byte_source::ByteSource;
use crate::cxx::path_escape_record::{EscapedPathStringRecord, path_escape_record_assign};
use crate::cxx::string_object::{StringObject, PrimaryStringRecord,
    string_object_construct_from_cstr, string_default_construct,
    string_object_destroy, primary_string_record_assign_from_string_object};
use crate::cxx::handle::handle_deref_or_null;
use crate::heap::block_mgr::block_manager_get;

/// Decoded layout; opaque spans retain their target byte sizes.
#[repr(C)]
pub struct NotesView {
    pub prefix: [u8; 0x58],
    pub path: EscapedPathStringRecord,
    pub path_flag: u8,
    pub opaque_6d: [u8; 0x67],
    pub cached_path_index: u32,
    pub opaque_d8: u32,
    pub selected_path: *mut EscapedPathStringRecord,
    pub selection_state: u32,
    pub opaque_e4: [u8; 0x408],
    pub source: ByteSource,
    pub opaque_4fc: [u8; 0x40],
    pub snapshot: u32,
    pub opaque_540: [u8; 0x64],
    pub request_handle: *const *mut u8,
    pub opaque_5a8: u32,
    /// The retail registration helper receives this embedded request's address.
    pub request: [u8; 0],
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(NotesView, path) == 0x58);
    assert!(core::mem::offset_of!(NotesView, path_flag) == 0x6c);
    assert!(core::mem::offset_of!(NotesView, cached_path_index) == 0xd4);
    assert!(core::mem::offset_of!(NotesView, selected_path) == 0xdc);
    assert!(core::mem::offset_of!(NotesView, selection_state) == 0xe0);
    assert!(core::mem::offset_of!(NotesView, source) == 0x4ec);
    assert!(core::mem::offset_of!(NotesView, snapshot) == 0x53c);
    assert!(core::mem::offset_of!(NotesView, request_handle) == 0x5a4);
    assert!(core::mem::offset_of!(NotesView, request) == 0x5ac);
};

type PreparePath = unsafe extern "C" fn(*mut NotesView);
type Propagate = unsafe extern "C" fn(*mut ByteSource, u32, u32);
type Register = unsafe extern "C" fn(*mut u8, *mut u8, u32, *mut *const *mut u8) -> u32;

unsafe extern "C" fn prepare_path(view: *mut NotesView) {
    (*view).cached_path_index = u32::MAX; // 0x08178e90: path + 0x7c.
    let mut temporary = core::mem::MaybeUninit::<StringObject>::uninit();
    let string = temporary.as_mut_ptr();
    string_object_construct_from_cstr(string, b"Notes\0".as_ptr());
    path_escape_record_assign(ptr::addr_of_mut!((*view).path), string);
    string_object_destroy(string);
    string_default_construct(string);
    primary_string_record_assign_from_string_object(
        ptr::addr_of_mut!((*view).path).cast::<PrimaryStringRecord>(), string);
    string_object_destroy(string);
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_propagate(_: *mut ByteSource, _: u32, _: u32) {
    panic!("install NOTES_VIEW_PROPAGATE before host use");
}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_register(_: *mut u8, _: *mut u8, _: u32, _: *mut *const *mut u8) -> u32 {
    panic!("install NOTES_VIEW_REGISTER before host use");
}

#[cfg(not(target_arch = "arm"))]
pub static mut NOTES_VIEW_PREPARE_PATH: PreparePath = prepare_path;
#[cfg(not(target_arch = "arm"))]
pub static mut NOTES_VIEW_PROPAGATE: Propagate = missing_propagate;
#[cfg(not(target_arch = "arm"))]
pub static mut NOTES_VIEW_REGISTER: Register = missing_register;
#[cfg(not(target_arch = "arm"))]
pub static mut NOTES_VIEW_GLOBAL_FLAG: *mut u8 = 0x089c_ffac as *mut u8;
#[cfg(not(target_arch = "arm"))]
pub static mut NOTES_VIEW_GLOBAL_WORD: *const u32 = 0x089c_a674 as *const u32;

/// Initializes the Notes path and conditionally registers its resource request.
///
/// # Safety
/// `view` and its embedded strings/byte source/handle must be initialized and
/// valid for their callees. Storage after `request` must accommodate the retail
/// request object. Globals and host boundaries must be valid; changing host
/// boundaries requires exclusive access.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn notes_view_initialize(view: *mut NotesView) {
    #[cfg(target_arch = "arm")]
    let (prepare, propagate, register, flag, word): (PreparePath, Propagate, Register, *mut u8, *const u32) = (
        prepare_path, core::mem::transmute(0x0827_25ecusize),
        core::mem::transmute(0x0818_a630usize), 0x089c_ffac as *mut u8, 0x089c_a674 as *const u32);
    #[cfg(not(target_arch = "arm"))]
    let (prepare, propagate, register, flag, word) = (
        NOTES_VIEW_PREPARE_PATH, NOTES_VIEW_PROPAGATE, NOTES_VIEW_REGISTER,
        NOTES_VIEW_GLOBAL_FLAG, NOTES_VIEW_GLOBAL_WORD);

    prepare(view);
    (*view).path_flag = 0;
    (*view).selected_path = ptr::addr_of_mut!((*view).path);
    (*view).selection_state = 0;
    (*view).source.status = 0;
    (*view).source.dirty = 0;
    for byte in &mut (*view).source.inline_bytes { *byte = 0; }
    ptr::write_volatile(flag, 0);
    propagate(ptr::addr_of_mut!((*view).source), 3, 1);
    (*view).snapshot = ptr::read_volatile(word);
    let handle = ptr::addr_of_mut!((*view).request_handle);
    if handle_deref_or_null(handle).is_null() {
        register(block_manager_get(), ptr::addr_of_mut!((*view).request).cast(), 0, handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    // Only external boundaries are replaced; tests exercise the exported port's
    // reset, snapshot, and double-indirection registration decision.
    unsafe extern "C" fn fixture_path(view: *mut NotesView) {
        (*view).cached_path_index = u32::MAX;
    }
    unsafe extern "C" fn fixture_propagate(source: *mut ByteSource, index: u32, value: u32) {
        assert_eq!((*source).inline_bytes, [0; 5]);
        assert_eq!((*source).status, 0);
        assert_eq!((*source).dirty, 0);
        assert_eq!(*NOTES_VIEW_GLOBAL_FLAG, 0);
        (*source).inline_bytes[index as usize] = value as u8;
        (*source).dirty = 1;
        // Snapshot must be read AFTER propagation, not hoisted before it.
        *(NOTES_VIEW_GLOBAL_WORD as *mut u32) = 0x12345678;
    }
    unsafe extern "C" fn forbidden_register(_: *mut u8, _: *mut u8, _: u32, _: *mut *const *mut u8) -> u32 {
        panic!("live handle must suppress registration");
    }
    unsafe extern "C" fn install_handle(_: *mut u8, _: *mut u8, _: u32, handle: *mut *const *mut u8) -> u32 {
        static mut CELL: *mut u8 = 1usize as *mut u8;
        handle.write(ptr::addr_of!(CELL));
        1
    }

    #[test]
    fn resets_flags_preserves_source_pointers_and_snapshots_after_propagation() {
        let _lock = LOCK.lock();
        unsafe {
            let mut view: NotesView = core::mem::zeroed();
            let mut flag = 9u8;
            let mut word = 0u32;
            let fallback = [9u8; 5];
            let overrides = [2u8; 5];
            let mut object = 7u8;
            let cell = ptr::addr_of_mut!(object);
            view.request_handle = ptr::addr_of!(cell);
            view.source.inline_bytes = [9; 5];
            view.source.status = 7;
            view.source.dirty = 8;
            view.source.padding = 0x5a;
            view.source.fallback_bytes = fallback.as_ptr();
            view.source.override_bytes = overrides.as_ptr();
            view.path_flag = 1;
            view.selection_state = 99;
            let saved = (NOTES_VIEW_PREPARE_PATH, NOTES_VIEW_PROPAGATE, NOTES_VIEW_REGISTER,
                NOTES_VIEW_GLOBAL_FLAG, NOTES_VIEW_GLOBAL_WORD);
            NOTES_VIEW_PREPARE_PATH = fixture_path;
            NOTES_VIEW_PROPAGATE = fixture_propagate;
            NOTES_VIEW_REGISTER = forbidden_register;
            NOTES_VIEW_GLOBAL_FLAG = ptr::addr_of_mut!(flag);
            NOTES_VIEW_GLOBAL_WORD = ptr::addr_of_mut!(word);
            notes_view_initialize(&mut view);
            assert_eq!(view.source.inline_bytes, [0, 0, 0, 1, 0]);
            assert_eq!(view.source.padding, 0x5a);
            assert_eq!(view.source.fallback_bytes, fallback.as_ptr());
            assert_eq!(view.source.override_bytes, overrides.as_ptr());
            assert_eq!(view.selected_path, ptr::addr_of_mut!(view.path));
            assert_eq!(view.path_flag, 0);
            assert_eq!(view.selection_state, 0);
            assert_eq!(view.snapshot, 0x12345678);
            assert_eq!(flag, 0);
            assert_eq!(view.request_handle, ptr::addr_of!(cell));
            (NOTES_VIEW_PREPARE_PATH, NOTES_VIEW_PROPAGATE, NOTES_VIEW_REGISTER,
                NOTES_VIEW_GLOBAL_FLAG, NOTES_VIEW_GLOBAL_WORD) = saved;
        }
    }

    #[test]
    fn both_empty_handle_levels_register_and_repeated_initialization_keeps_live_handle() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = (NOTES_VIEW_PREPARE_PATH, NOTES_VIEW_PROPAGATE, NOTES_VIEW_REGISTER,
                NOTES_VIEW_GLOBAL_FLAG, NOTES_VIEW_GLOBAL_WORD);
            let mut flag = 1u8;
            let mut word = 0u32;
            let empty_cell = ptr::null_mut();
            NOTES_VIEW_PREPARE_PATH = fixture_path;
            NOTES_VIEW_PROPAGATE = fixture_propagate;
            NOTES_VIEW_REGISTER = install_handle;
            NOTES_VIEW_GLOBAL_FLAG = ptr::addr_of_mut!(flag);
            NOTES_VIEW_GLOBAL_WORD = ptr::addr_of_mut!(word);
            for initial in [ptr::null(), ptr::addr_of!(empty_cell)] {
                let mut view: NotesView = core::mem::zeroed();
                view.request_handle = initial;
                notes_view_initialize(&mut view);
                assert!(!handle_deref_or_null(ptr::addr_of!(view.request_handle)).is_null());
                NOTES_VIEW_REGISTER = forbidden_register;
                notes_view_initialize(&mut view);
                NOTES_VIEW_REGISTER = install_handle;
            }
            (NOTES_VIEW_PREPARE_PATH, NOTES_VIEW_PROPAGATE, NOTES_VIEW_REGISTER,
                NOTES_VIEW_GLOBAL_FLAG, NOTES_VIEW_GLOBAL_WORD) = saved;
        }
    }
}
