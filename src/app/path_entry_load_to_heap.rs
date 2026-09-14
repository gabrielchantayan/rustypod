//! Path-entry buffered load followed by a heap-owned copy.
//!
//! Port: [`path_entry_load_to_heap`] — original: `FUN_08072af8` at
//! **0x08072af8** (188 bytes, `0x08072af8..0x08072bb4`). Raw decoding of
//! every immediate ARM `B`/`BL` word in `osos.dec` verifies **six inbound
//! direct call sites**, all unconditional `bl` (none predicated):
//! `0x082db884`, `0x0832152c`, `0x08329bb4`, `0x08329e4c`, `0x0832a05c`, and
//! `0x0832a7c4`.
//!
//! The entry has a completion byte at +0x00, an embedded path object at +0x04,
//! and its signed facade hint at +0x0c. After validating all three pointers,
//! the routine probes the path, builds a 100-byte buffered-load state on its
//! stack, copies its completed byte buffer into `malloc` storage, marks the
//! entry complete, returns that allocation and byte length, then resets the
//! aligned staging buffer. It returns `0xffffffce` for invalid pointers,
//! `0xffffffd5` for an absent path, `0xffffff94` for allocation failure, and
//! zero after a complete copy.
//!
//! The buffered loader at `0x081e1ea0` is not ported. Its established ABI and
//! output layout are preserved as a volatile dispatch boundary: target builds
//! call the fixed firmware entry, while the host default produces an empty
//! state (the preceding host path probe fails closed, so that default is not
//! reached in normal host use). No concrete identity beyond its buffered-load
//! behavior is claimed.

use core::mem::MaybeUninit;

use crate::app::path_probe::path_probe_via_facade;
use crate::cxx::string_object::StringObject;
use crate::heap::aligned_buffer::aligned_buffer_reset;
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::runtime::malloc_rt::malloc;

/// Firmware address of the unported helper invoked after the path probe.
pub const PATH_BUFFER_LOAD_ADDRESS: usize = 0x081e_1ea0;

const INVALID_ARGUMENT: u32 = 0xffff_ffce;
const PATH_ABSENT: u32 = 0xffff_ffd5;
const ALLOCATION_FAILED: u32 = 0xffff_ff94;
const PATH_OFFSET: usize = 0x04;
const PATH_HINT_OFFSET: usize = 0x0c;
const BUFFER_OFFSET: usize = 0x54;

/// The 100-byte stack object constructed by `FUN_081e1ea0`.
///
/// Its fields read by this caller are the aligned buffer at +0x54 and the
/// completed byte length at +0x5c. The status word at +0x60 is retained to
/// preserve the verified helper layout although this caller never reads it.
#[repr(C)]
pub struct PathBufferLoadState {
    opaque: [u8; BUFFER_OFFSET],
    data: u32,
    allocation: u32,
    len: u32,
    status: u32,
}

/// ABI of the unported buffered-load helper at [`PATH_BUFFER_LOAD_ADDRESS`].
pub type PathBufferLoad = unsafe extern "C" fn(
    state: *mut PathBufferLoadState,
    path: *mut StringObject,
    path_hint: u32,
) -> *mut PathBufferLoadState;

unsafe extern "C" fn firmware_path_buffer_load(
    state: *mut PathBufferLoadState,
    path: *mut StringObject,
    path_hint: u32,
) -> *mut PathBufferLoadState {
    #[cfg(target_os = "none")]
    {
        let load: PathBufferLoad = core::mem::transmute(PATH_BUFFER_LOAD_ADDRESS);
        return load(state, path, path_hint);
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (path, path_hint);
        state.write(PathBufferLoadState {
            opaque: [0; BUFFER_OFFSET],
            data: 0,
            allocation: 0,
            len: 0,
            status: 0,
        });
        state
    }
}

/// Active buffered-load boundary. The volatile load at its call site prevents
/// LLVM from replacing the target default with an inferred library operation.
pub static mut PATH_BUFFER_LOAD: PathBufferLoad = firmware_path_buffer_load;

#[inline(always)]
unsafe fn path_buffer_load_fn() -> PathBufferLoad {
    core::ptr::read_volatile(core::ptr::addr_of!(PATH_BUFFER_LOAD))
}

/// path_entry_load_to_heap — original: `FUN_08072af8` @ **0x08072af8**
/// (188 bytes; six inbound direct plain-`bl` call sites, no predicated forms).
///
/// Probes `entry + 4` using the sign-extended byte at `entry + 12`, asks the
/// buffered-load boundary to fill its 100-byte staging state, then allocates
/// and copies exactly the state's +0x5c byte count. On success it stores the
/// completion byte before the copy, writes length before allocation to the two
/// output slots, resets the staging buffer, and returns zero. The error paths
/// retain all caller outputs and the completion byte exactly as the ARM does.
///
/// # Deliberate deviation
///
/// The separately linked buffered-load helper remains [`PATH_BUFFER_LOAD`].
/// Its target default invokes the verified retailOS entry through a volatile
/// function pointer; host tests install a layout-valid recording model.
///
/// # Safety
///
/// `entry` must cover byte +0x0c and contain an embedded path object at +0x04.
/// `out_allocation` and `out_len` must be writable words. On success the
/// caller owns the returned `malloc` allocation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_entry_load_to_heap(
    entry: *mut u8,
    out_allocation: *mut *mut u8,
    out_len: *mut u32,
) -> u32 {
    if entry.is_null() || out_allocation.is_null() || out_len.is_null() {
        return INVALID_ARGUMENT;
    }

    let path_hint = entry.add(PATH_HINT_OFFSET).read() as i8 as i32 as u32;
    let path = entry.add(PATH_OFFSET).cast::<StringObject>();
    if path_probe_via_facade(path, path_hint) == 0 {
        return PATH_ABSENT;
    }

    let mut storage = MaybeUninit::<PathBufferLoadState>::uninit();
    let state = storage.as_mut_ptr();
    path_buffer_load_fn()(state, path, path_hint);

    let len = core::ptr::addr_of!((*state).len).read();
    let allocation = malloc(len as usize);
    if allocation.is_null() {
        aligned_buffer_reset(core::ptr::addr_of_mut!((*state).data).cast());
        return ALLOCATION_FAILED;
    }

    entry.write(1);
    let data = core::ptr::addr_of!((*state).data).read() as usize as *const u8;
    __rt_memcpy(allocation, data, len as usize);
    out_len.write(len);
    out_allocation.write(allocation);
    aligned_buffer_reset(core::ptr::addr_of_mut!((*state).data).cast());
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::path_probe::{
        FacadeObject, FacadeVtable, GuardConstruct, GuardDestroy, InterfaceGuard, PathProbeQuery,
        FACADE_PATH_PROBE_SLOT_INDEX, FACADE_VTABLE_SLOTS, PATH_PROBE_FACADE_FETCH,
        PATH_PROBE_GUARD_CTOR, PATH_PROBE_GUARD_DTOR,
    };
    use crate::runtime::malloc_rt::{HeapOps, DEFAULT_MALLOC_RT_OPS, HEAP_OPS};
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    static PATH_ENTRY_LOAD_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PROBE_STATUS: u32 = 0;
    static mut PROBE_PATH: *mut StringObject = core::ptr::null_mut();
    static mut HELPER_PATH: *mut StringObject = core::ptr::null_mut();
    static mut HELPER_HINT: u32 = 0;
    static mut HELPER_CALLS: usize = 0;
    static mut HELPER_DATA: u32 = 0;
    static mut HELPER_LEN: u32 = 0;
    static mut ALLOC_FAIL: bool = false;
    static mut ALLOC_SIZE: usize = 0;
    static mut ALLOC_CAPACITY: usize = 0;
    static mut MOCK_VTABLE: FacadeVtable = FacadeVtable {
        slots: [0; FACADE_VTABLE_SLOTS],
    };
    static mut MOCK_FACADE: FacadeObject = FacadeObject {
        vtable: core::ptr::null(),
    };

    struct SeamGuard {
        saved_heap_ops: HeapOps,
    }

    impl SeamGuard {
        unsafe fn new() -> Self {
            SeamGuard {
                saved_heap_ops: core::ptr::addr_of!(HEAP_OPS).read_volatile(),
            }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PATH_BUFFER_LOAD).write_volatile(firmware_path_buffer_load);
                core::ptr::addr_of_mut!(HEAP_OPS).write_volatile(self.saved_heap_ops);
                crate::app::path_probe::tests::restore_firmware_seams();
            }
        }
    }

    unsafe extern "C" fn recording_guard_ctor(
        guard: *mut InterfaceGuard,
        _hint: u32,
    ) -> *mut InterfaceGuard {
        guard
    }

    unsafe extern "C" fn recording_facade_fetch(
        _guard: *mut InterfaceGuard,
        _selector: u32,
    ) -> *mut FacadeObject {
        core::ptr::addr_of_mut!(MOCK_FACADE)
    }

    unsafe extern "C" fn recording_path_probe(
        _facade: *mut FacadeObject,
        path: *mut StringObject,
    ) -> u32 {
        PROBE_PATH = path;
        PROBE_STATUS
    }

    unsafe extern "C" fn recording_guard_destroy(guard: *mut InterfaceGuard) -> *mut InterfaceGuard {
        guard
    }

    unsafe extern "C" fn recording_buffer_load(
        state: *mut PathBufferLoadState,
        path: *mut StringObject,
        hint: u32,
    ) -> *mut PathBufferLoadState {
        HELPER_CALLS += 1;
        HELPER_PATH = path;
        HELPER_HINT = hint;
        core::ptr::addr_of_mut!((*state).data).write(HELPER_DATA);
        core::ptr::addr_of_mut!((*state).allocation).write(0);
        core::ptr::addr_of_mut!((*state).len).write(HELPER_LEN);
        core::ptr::addr_of_mut!((*state).status).write(0);
        state
    }

    unsafe extern "C" fn recording_alloc(size: usize) -> *mut u8 {
        ALLOC_SIZE = size;
        if ALLOC_FAIL {
            return core::ptr::null_mut();
        }
        let mut bytes = vec![0_u8; size + 16];
        let ptr = bytes.as_mut_ptr();
        ALLOC_CAPACITY = bytes.capacity();
        core::mem::forget(bytes);
        ptr
    }

    unsafe extern "C" fn noop_free(_ptr: *mut u8) {}
    unsafe extern "C" fn noop_realloc(_ptr: *mut u8, _size: usize) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn noop_grow(_size: usize, _base: *mut usize) -> usize { 0 }
    unsafe extern "C" fn noop_raise(_signal: i32, _code: i32) -> i32 { 0 }

    const RECORDING_HEAP_OPS: HeapOps = HeapOps {
        alloc: recording_alloc,
        free: noop_free,
        realloc: noop_realloc,
        grow: noop_grow,
        raise: noop_raise,
    };

    unsafe fn install_recording(probe_status: u32) {
        PROBE_STATUS = probe_status;
        PROBE_PATH = core::ptr::null_mut();
        HELPER_PATH = core::ptr::null_mut();
        HELPER_HINT = 0;
        HELPER_CALLS = 0;
        HELPER_DATA = 0;
        HELPER_LEN = 0;
        ALLOC_FAIL = false;
        ALLOC_SIZE = 0;
        ALLOC_CAPACITY = 0;
        (*core::ptr::addr_of_mut!(MOCK_VTABLE)).slots = [0; FACADE_VTABLE_SLOTS];
        (*core::ptr::addr_of_mut!(MOCK_VTABLE)).slots[FACADE_PATH_PROBE_SLOT_INDEX] =
            recording_path_probe as PathProbeQuery as usize;
        (*core::ptr::addr_of_mut!(MOCK_FACADE)).vtable =
            core::ptr::addr_of!(MOCK_VTABLE);
        core::ptr::addr_of_mut!(PATH_PROBE_GUARD_CTOR)
            .write_volatile(recording_guard_ctor as GuardConstruct);
        core::ptr::addr_of_mut!(PATH_PROBE_FACADE_FETCH).write_volatile(recording_facade_fetch);
        core::ptr::addr_of_mut!(PATH_PROBE_GUARD_DTOR)
            .write_volatile(recording_guard_destroy as GuardDestroy);
        core::ptr::addr_of_mut!(PATH_BUFFER_LOAD).write_volatile(recording_buffer_load);
        core::ptr::addr_of_mut!(HEAP_OPS).write_volatile(RECORDING_HEAP_OPS);
    }

    fn take_locks() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let local = PATH_ENTRY_LOAD_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let probe = crate::app::path_probe::tests::PATH_PROBE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let heap = crate::runtime::malloc_rt::tests::lock_ops();
        (local, probe, heap)
    }

    #[test]
    fn rejects_any_null_argument_without_side_effects() {
        let _locks = take_locks();
        let _seams = unsafe { SeamGuard::new() };
        let mut entry = [0x5a_u8; 16];
        let mut allocation = 0x1234usize as *mut u8;
        let mut len = 0x5678_u32;

        unsafe {
            assert_eq!(path_entry_load_to_heap(core::ptr::null_mut(), &mut allocation, &mut len), INVALID_ARGUMENT);
            assert_eq!(path_entry_load_to_heap(entry.as_mut_ptr(), core::ptr::null_mut(), &mut len), INVALID_ARGUMENT);
            assert_eq!(path_entry_load_to_heap(entry.as_mut_ptr(), &mut allocation, core::ptr::null_mut()), INVALID_ARGUMENT);
        }
        assert_eq!(entry[0], 0x5a);
        assert_eq!(allocation as usize, 0x1234);
        assert_eq!(len, 0x5678);
    }

    #[test]
    fn absent_path_preserves_entry_and_outputs() {
        let _locks = take_locks();
        let _seams = unsafe { SeamGuard::new() };
        unsafe { install_recording(0) };
        let mut entry = [0x5a_u8; 16];
        entry[PATH_HINT_OFFSET] = 0x80;
        let mut allocation = 0x1234usize as *mut u8;
        let mut len = 0x5678_u32;

        let status = unsafe { path_entry_load_to_heap(entry.as_mut_ptr(), &mut allocation, &mut len) };
        assert_eq!(status, PATH_ABSENT);
        assert_eq!(entry[0], 0x5a);
        assert_eq!(allocation as usize, 0x1234);
        assert_eq!(len, 0x5678);
        unsafe {
            assert_eq!(PROBE_PATH, entry.as_mut_ptr().add(PATH_OFFSET).cast());
            assert_eq!(HELPER_CALLS, 0);
            assert_eq!(ALLOC_SIZE, 0);
        }
    }

    #[test]
    fn allocation_failure_resets_buffer_and_preserves_outputs() {
        let _locks = take_locks();
        let _seams = unsafe { SeamGuard::new() };
        unsafe {
            install_recording(7);
            HELPER_LEN = 12;
            ALLOC_FAIL = true;
        }
        let mut entry = [0x5a_u8; 16];
        entry[PATH_HINT_OFFSET] = 0xfe;
        let mut allocation = 0x1234usize as *mut u8;
        let mut len = 0x5678_u32;

        let status = unsafe { path_entry_load_to_heap(entry.as_mut_ptr(), &mut allocation, &mut len) };
        assert_eq!(status, ALLOCATION_FAILED);
        assert_eq!(entry[0], 0x5a);
        assert_eq!(allocation as usize, 0x1234);
        assert_eq!(len, 0x5678);
        unsafe {
            assert_eq!(HELPER_CALLS, 1);
            assert_eq!(HELPER_PATH, entry.as_mut_ptr().add(PATH_OFFSET).cast());
            assert_eq!(HELPER_HINT, 0xffff_fffe);
            assert_eq!(ALLOC_SIZE, 12);
        }
    }

    #[test]
    fn copies_completed_buffer_and_marks_entry() {
        let _locks = take_locks();
        let _seams = unsafe { SeamGuard::new() };
        let source = match crate::testing::try_map_u32_slab(
            crate::testing::hints::PATH_ENTRY_LOAD_TO_HEAP,
            0x1000,
        ) {
            Some(source) => source,
            None => {
                crate::testing::note_missing_u32_fixture("app/path_entry_load_to_heap");
                return;
            }
        };
        let payload = [0x31_u8, 0x00, 0xa7, 0x5c, 0xfe, 0x19, 0x80];
        unsafe {
            source.copy_from_nonoverlapping(payload.as_ptr(), payload.len());
            install_recording(7);
            HELPER_DATA = source as usize as u32;
            HELPER_LEN = payload.len() as u32;
        }
        let mut entry = [0x5a_u8; 16];
        entry[PATH_HINT_OFFSET] = 0xfe;
        let mut allocation = core::ptr::null_mut();
        let mut len = 0_u32;

        let status = unsafe { path_entry_load_to_heap(entry.as_mut_ptr(), &mut allocation, &mut len) };
        assert_eq!(status, 0);
        assert_eq!(entry[0], 1);
        assert_eq!(len, payload.len() as u32);
        assert!(!allocation.is_null());
        unsafe {
            assert_eq!(PROBE_PATH, entry.as_mut_ptr().add(PATH_OFFSET).cast());
            assert_eq!(HELPER_CALLS, 1);
            assert_eq!(HELPER_PATH, entry.as_mut_ptr().add(PATH_OFFSET).cast());
            assert_eq!(HELPER_HINT, 0xffff_fffe);
            assert_eq!(ALLOC_SIZE, payload.len());
            assert_eq!(core::slice::from_raw_parts(allocation, payload.len()), payload);
            drop(Vec::from_raw_parts(allocation, ALLOC_CAPACITY, ALLOC_CAPACITY));
        }
    }
}
