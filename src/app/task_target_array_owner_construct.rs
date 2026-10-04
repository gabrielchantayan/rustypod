//! Task-target array owner constructor, `FUN_08201de0` @ 0x08201de0.
//! True extent: 156 bytes, [0x08201de0, 0x08201e7c): 148 code bytes and
//! vtable literals 0x08990f28 and 0x089a5490. Next function: 0x08201e7c.
//! Whole-image A32 decoding: two inbound plain BLs (0x08236170,
//! 0x08237320), four outbound plain BLs, zero predicated BLs either way.
//! Construct the task-target framework base with create_link=1, allocate
//! and construct a 308-byte child, then construct the embedded observable
//! array and initialize flags, sentinel indices and trailing state.
//! The final owner is rebased from the array constructor's returned pointer.
//!
//! Deviations: target fields use word indices even on hosts; host operations
//! replace the native-pointer framework layout and resident child constructor.
//! The child's class identity is unknown; device execution uses its verified
//! entry at 0x082022ac. No NULL guards or blanket zeroing are added.
#[cfg(target_os = "none")]

use crate::app::class_6800::framework_base_construct_with_task_target;
use crate::cxx::observable_array::{observable_array_construct, ObservableArray};
use crate::heap::veneers::operator_new;

pub type Construct = unsafe extern "C" fn(*mut u8) -> *mut u8;
#[derive(Clone, Copy)]
pub struct TaskTargetArrayOwnerConstructOps {
    pub base: Construct,
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
    pub child: Construct,
    pub array: Construct,
}
#[cfg(target_os = "none")]

unsafe extern "C" fn base(storage: *mut u8) -> *mut u8 {
    framework_base_construct_with_task_target(storage.cast(), 1).cast()
}
unsafe extern "C" fn array(storage: *mut u8) -> *mut u8 {
    observable_array_construct(storage.cast::<ObservableArray>()).cast()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_constructor(_: *mut u8) -> *mut u8 {
    panic!("install task-target array owner host constructors")
}
#[cfg(not(target_os = "none"))]
pub static mut TASK_TARGET_ARRAY_OWNER_CONSTRUCT_OPS: TaskTargetArrayOwnerConstructOps =
    TaskTargetArrayOwnerConstructOps {
        base: missing_constructor, allocate: operator_new,
        child: missing_constructor, array,
    };

/// Construct in at least 112 word-aligned writable bytes.
///
/// # Safety
/// Storage and current task must satisfy the framework constructor. The
/// allocator must supply 308 writable bytes for the resident child. Host
/// operations must be installed; the stored child pointer must fit u32.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_target_array_owner_construct(storage: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    let ops = TaskTargetArrayOwnerConstructOps {
        base, allocate: operator_new, child: core::mem::transmute(0x0820_22acusize), array,
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(TASK_TARGET_ARRAY_OWNER_CONSTRUCT_OPS).read();
    construct(storage, ops)
}

unsafe fn construct(storage: *mut u8, ops: TaskTargetArrayOwnerConstructOps) -> *mut u8 {
    let owner = (ops.base)(storage);
    let words = owner.cast::<u32>();
    words.write_volatile(0x0899_0f28);
    owner.add(20).write(0);
    owner.add(21).write(0);
    words.add(6).write(0);
    let child = (ops.child)((ops.allocate)(308));
    words.add(7).write(child as usize as u32);
    words.add(8).write(0);
    let array = (ops.array)(owner.add(40));
    let words = array.cast::<u32>();
    words.write_volatile(0x089a_5490);
    array.add(16).write(0);
    words.add(6).write(u32::MAX);
    words.add(5).write(0);
    words.add(9).write(u32::MAX);
    let owner = array.sub(40);
    owner.add(88).write(0);
    owner.add(89).write(1);
    let words = owner.cast::<u32>();
    words.add(24).write(u32::MAX);
    words.add(23).write(0);
    owner.add(100).write(0);
    owner.add(101).write(0);
    owner.add(102).write(1);
    owner.add(103).write(0);
    words.add(26).write(0);
    words.add(27).write(0);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn identity(storage: *mut u8) -> *mut u8 { storage }
    unsafe extern "C" fn allocate(_: usize) -> *mut u8 { 0x1234_0000 as *mut u8 }
    unsafe extern "C" fn child(_: *mut u8) -> *mut u8 { 0x1234_0040 as *mut u8 }
    unsafe extern "C" fn null_child(_: *mut u8) -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn relocated_base(storage: *mut u8) -> *mut u8 { storage.add(112) }
    unsafe extern "C" fn relocated_array(storage: *mut u8) -> *mut u8 { array(storage.add(112)) }

    #[test]
    fn exact_initialization_preserves_unwritten_bytes_and_stores_child_result() {
        for (child, child_result) in [(child as Construct, 0x1234_0040), (null_child as Construct, 0)] {
            let mut storage = [0xa5a5_a5a5u32; 30];
            let pointer = storage.as_mut_ptr().cast::<u8>();
            let ops = TaskTargetArrayOwnerConstructOps { base: identity, allocate, child, array };
            assert_eq!(unsafe { construct(pointer, ops) }, pointer);
            let mut expected = [0xa5a5_a5a5u32; 30];
            expected[0] = 0x08990f28;
            expected[5] = 0xa5a50000;
            expected[6] = 0;
            expected[7] = child_result;
            expected[8] = 0;
            expected[10] = 0x089a5490;
            expected[11..14].fill(0);
            expected[14] = 0xa5a5a500;
            expected[15] = 0;
            expected[16] = u32::MAX;
            expected[19] = u32::MAX;
            expected[22] = 0xa5a50100;
            expected[23] = 0;
            expected[24] = u32::MAX;
            expected[25] = 0x00010000;
            expected[26..28].fill(0);
            assert_eq!(storage, expected);
        }
    }

    #[test]
    fn base_and_member_returns_relocate_disjoint_store_groups() {
        let mut storage = [0xa5a5_a5a5u32; 86];
        let pointer = storage.as_mut_ptr().cast::<u8>();
        let ops = TaskTargetArrayOwnerConstructOps {
            base: relocated_base, allocate, child, array: relocated_array,
        };
        assert_eq!(unsafe { construct(pointer, ops) }, unsafe { pointer.add(224) });
        assert_eq!(&storage[..28], &[0xa5a5_a5a5; 28]);
        assert_eq!(storage[28], 0x08990f28);
        assert_eq!(storage[35], 0x12340040);
        assert_eq!(&storage[38..56], &[0xa5a5_a5a5; 18]);
        assert_eq!(storage[66], 0x089a5490);
        assert_eq!(&storage[67..70], &[0; 3]);
        assert_eq!(storage[72], u32::MAX);
        assert_eq!(storage[78], 0xa5a50100);
        assert_eq!(storage[80], u32::MAX);
        assert_eq!(storage[81], 0x00010000);
        assert_eq!(&storage[82..84], &[0; 2]);
        assert_eq!(&storage[84..], &[0xa5a5_a5a5; 2]);
    }
}
