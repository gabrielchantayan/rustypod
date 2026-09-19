//! FreeType face-release entry point.

use core::ffi::c_void;

use crate::ft::error::{FT_ERR_INVALID_FACE_HANDLE, FT_ERR_OK};
use crate::ft::glyph_slot::FtFace;
use crate::ft::list::{ft_list_find, FtList, FtListNode};
use crate::ft::memory::{ft_mem_free, FtMemory};

/// The `FT_DriverRec` prefix used by `FT_Done_Face`. On ARM, `memory` is at
/// +0x08 and `faces_list` is at +0x18. The three words between them belong to
/// the driver's class/format state and are not read here.
#[repr(C)]
pub struct FtDriver {
    pub module_class: *mut c_void,
    pub library: *mut c_void,
    pub memory: *mut FtMemory,
    _before_faces_list: [u32; 3],
    pub faces_list: FtList,
}

type FtListRemove = unsafe extern "C" fn(*mut FtList, *mut FtListNode);
type FtFaceDestroy = unsafe extern "C" fn(*mut FtMemory, *mut FtFace, *mut FtDriver);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn list_remove(list: *mut FtList, node: *mut FtListNode) {
    let remove: FtListRemove = core::mem::transmute(0x0804_cb4cusize);
    remove(list, node);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_face(memory: *mut FtMemory, face: *mut FtFace, driver: *mut FtDriver) {
    let destroy: FtFaceDestroy = core::mem::transmute(0x0807_c2f8usize);
    destroy(memory, face, driver);
}

#[cfg(not(target_os = "none"))]
static mut LIST_REMOVE: FtListRemove = host_list_remove;
#[cfg(not(target_os = "none"))]
static mut FACE_DESTROY: FtFaceDestroy = host_face_destroy;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_list_remove(_list: *mut FtList, _node: *mut FtListNode) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_face_destroy(
    _memory: *mut FtMemory,
    _face: *mut FtFace,
    _driver: *mut FtDriver,
) {
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn list_remove(list: *mut FtList, node: *mut FtListNode) {
    core::ptr::read_volatile(core::ptr::addr_of!(LIST_REMOVE))(list, node);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_face(memory: *mut FtMemory, face: *mut FtFace, driver: *mut FtDriver) {
    core::ptr::read_volatile(core::ptr::addr_of!(FACE_DESTROY))(memory, face, driver);
}

/// `ft_done_face` — original: `FUN_0804c360` @ **0x0804c360** (100 bytes;
/// `0x0804c360..0x0804c3c4`). Raw `osos.dec` establishes the extent from the
/// six-register prologue through its return; `0x0804c3c4` starts a distinct
/// function. The body has four plain outgoing `bl` calls and no predicated
/// calls. Whole-image A32 decoding finds three plain incoming `bl` calls
/// (0x0804da08, 0x0812e4bc, 0x0819d9c4) and one predicated `blne`
/// (0x08080798).
///
/// FreeType 2.3 `FT_Done_Face` (`src/base/ftobjs.c`): reject a null face or
/// missing driver with `FT_Err_Invalid_Face_Handle`; find the face in the
/// driver's face list, unlink and free its list node, then destroy the face
/// through the driver's allocator. Deliberate deviations: unported
/// `FT_List_Remove` @ 0x0804cb4c and the face-destruction helper @
/// 0x0807c2f8 remain fixed-address target seams; host tests replace them to
/// verify call order and arguments.
///
/// # Safety
/// A non-null `face` must contain a valid driver, whose list and allocator
/// are valid. The original has the same requirements after its two null gates.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_done_face(face: *mut FtFace) -> i32 {
    if face.is_null() {
        return FT_ERR_INVALID_FACE_HANDLE;
    }
    let driver = (*face).driver.cast::<FtDriver>();
    if driver.is_null() {
        return FT_ERR_INVALID_FACE_HANDLE;
    }

    let memory = (*driver).memory;
    let list = core::ptr::addr_of_mut!((*driver).faces_list);
    let node = ft_list_find(list, face.cast());
    if node.is_null() {
        return FT_ERR_INVALID_FACE_HANDLE;
    }

    list_remove(list, node);
    ft_mem_free(memory, node.cast());
    destroy_face(memory, face, driver);
    FT_ERR_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use core::sync::atomic::{AtomicU32, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static EVENT_SEQUENCE: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn list_remove_recorder(list: *mut FtList, node: *mut FtListNode) {
        EVENT_SEQUENCE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| Some(value * 10 + 1)).unwrap();
        (*list).head = (*node).next;
        if !(*node).next.is_null() {
            (*(*node).next).prev = ptr::null_mut();
        }
    }

    unsafe extern "C" fn free_recorder(_memory: *mut FtMemory, _block: *mut u8) {
        EVENT_SEQUENCE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| Some(value * 10 + 2)).unwrap();
    }

    unsafe extern "C" fn destroy_recorder(
        _memory: *mut FtMemory,
        _face: *mut FtFace,
        _driver: *mut FtDriver,
    ) {
        EVENT_SEQUENCE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| Some(value * 10 + 3)).unwrap();
    }

    unsafe extern "C" fn alloc_unused(_memory: *mut FtMemory, _size: i32) -> *mut u8 {
        ptr::null_mut()
    }
    unsafe extern "C" fn realloc_unused(
        _memory: *mut FtMemory,
        _old: i32,
        _new: i32,
        _block: *mut u8,
    ) -> *mut u8 {
        ptr::null_mut()
    }

    fn allocator() -> FtMemory {
        FtMemory {
            user: ptr::null_mut(),
            alloc: alloc_unused,
            free: free_recorder,
            realloc: realloc_unused,
        }
    }

    #[test]
    fn rejects_null_face_and_missing_driver_without_calls() {
        let _lock = TEST_LOCK.lock();
        EVENT_SEQUENCE.store(0, Ordering::Relaxed);
        unsafe {
            LIST_REMOVE = list_remove_recorder;
            FACE_DESTROY = destroy_recorder;
        }
        assert_eq!(unsafe { ft_done_face(ptr::null_mut()) }, FT_ERR_INVALID_FACE_HANDLE);
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { ft_done_face(&mut face) }, FT_ERR_INVALID_FACE_HANDLE);
        assert_eq!(EVENT_SEQUENCE.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rejects_face_absent_from_driver_list_without_calls() {
        let _lock = TEST_LOCK.lock();
        EVENT_SEQUENCE.store(0, Ordering::Relaxed);
        let mut memory = allocator();
        let mut driver = FtDriver {
            module_class: ptr::null_mut(), library: ptr::null_mut(), memory: &mut memory,
            _before_faces_list: [0; 3],
            faces_list: FtList { head: ptr::null_mut(), tail: ptr::null_mut() },
        };
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        face.driver = (&mut driver as *mut FtDriver).cast();
        assert_eq!(unsafe { ft_done_face(&mut face) }, FT_ERR_INVALID_FACE_HANDLE);
        assert_eq!(EVENT_SEQUENCE.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unlinks_frees_then_destroys_listed_face() {
        let _lock = TEST_LOCK.lock();
        EVENT_SEQUENCE.store(0, Ordering::Relaxed);
        unsafe {
            LIST_REMOVE = list_remove_recorder;
            FACE_DESTROY = destroy_recorder;
        }
        let mut memory = allocator();
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        let mut node = FtListNode { prev: ptr::null_mut(), next: ptr::null_mut(), data: (&mut face as *mut FtFace).cast() };
        let mut driver = FtDriver {
            module_class: ptr::null_mut(), library: ptr::null_mut(), memory: &mut memory,
            _before_faces_list: [0; 3],
            faces_list: FtList { head: &mut node, tail: &mut node },
        };
        face.driver = (&mut driver as *mut FtDriver).cast();

        assert_eq!(unsafe { ft_done_face(&mut face) }, FT_ERR_OK);
        assert!(driver.faces_list.head.is_null());
        assert_eq!(EVENT_SEQUENCE.load(Ordering::Relaxed), 123);
    }
}
