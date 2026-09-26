//! Append a 12-byte path record to a path-object vector.
//!
//! Source: retailOS `FUN_083de12c` at load address `0x083de12c`.
//! Raw `osos.dec` has a true 100-byte extent: `push {r4-r6,lr}` at
//! `0x083de12c` through `pop {r4-r6,pc}` at `0x083de18c`; the next real
//! function starts at `0x083de190`. It has two plain `bl` calls
//! (`container_is_empty_alias_75c0` and the grow routine) and one predicated
//! `blne` to `path_object_copy_construct`.
//!
//! The routine grows the vector when it is empty or its insertion cursor has
//! reached capacity, copies the record's leading word and embedded path object
//! into a non-null cursor, then advances the cursor by 12 bytes and increments
//! the item count. Deliberate deviations: the unported grow routine at
//! `0x083ddd80` and the existing path-object copy constructor at `0x082792b4`
//! remain explicit seams; host tests supply them directly.

#[cfg(target_os = "none")]
use core::mem::transmute;

type VectorIsEmpty = unsafe extern "C" fn(*mut u8) -> u32;
type VectorGrow = unsafe extern "C" fn(*mut u8);
type PathObjectCopyConstruct = unsafe extern "C" fn(*mut u8, *const u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_vector_is_empty(vector: *mut u8) -> u32 {
    unsafe { transmute::<usize, VectorIsEmpty>(0x083d_75c0)(vector) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_vector_is_empty(_: *mut u8) -> u32 {
    panic!("path_object_vector_push_back requires retail emptiness predicate")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_vector_grow(vector: *mut u8) {
    unsafe { transmute::<usize, VectorGrow>(0x083d_dd80)(vector) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_vector_grow(_: *mut u8) {
    panic!("path_object_vector_push_back requires retail grow routine")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_path_object_copy_construct(destination: *mut u8, source: *const u8) {
    unsafe { transmute::<usize, PathObjectCopyConstruct>(0x0827_92b4)(destination, source) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_path_object_copy_construct(_: *mut u8, _: *const u8) {
    panic!("path_object_vector_push_back requires path-object copy constructor")
}

unsafe fn path_object_vector_push_back_with(
    vector: *mut u8,
    record: *const u8,
    is_empty: VectorIsEmpty,
    grow: VectorGrow,
    copy_construct: PathObjectCopyConstruct,
) {
    unsafe {
        let cursor = vector.add(0x10).cast::<u32>();
        if is_empty(vector) != 0 || cursor.read() == vector.add(0x18).cast::<u32>().read() {
            grow(vector);
        }

        let destination = cursor.read() as usize as *mut u8;
        if !destination.is_null() {
            destination.cast::<u32>().write(record.cast::<u32>().read());
            copy_construct(destination.add(4), record.add(4));
        }
        cursor.write((destination as usize as u32).wrapping_add(12));
        let count = vector.add(0x20).cast::<u32>();
        count.write(count.read().wrapping_add(1));
    }
}

/// Appends `record` to `vector`.
///
/// # Safety
/// `vector` must use the retail 32-bit layout and `record` must point to its
/// 12-byte record representation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_object_vector_push_back(vector: *mut u8, record: *const u8) {
    unsafe {
        path_object_vector_push_back_with(
            vector,
            record,
            firmware_vector_is_empty,
            firmware_vector_grow,
            firmware_path_object_copy_construct,
        );
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    use super::*;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static EMPTY: AtomicU32 = AtomicU32::new(0);
    static GROW_CALLS: AtomicU32 = AtomicU32::new(0);
    static COPY_CALLS: AtomicU32 = AtomicU32::new(0);
    static GROW_STORAGE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn is_empty(_: *mut u8) -> u32 { EMPTY.load(Ordering::SeqCst) }
    unsafe extern "C" fn grow(vector: *mut u8) {
        unsafe {
            GROW_CALLS.fetch_add(1, Ordering::SeqCst);
            let storage = GROW_STORAGE.load(Ordering::SeqCst) as *mut u8;
            vector.add(0x10).cast::<u32>().write(storage as usize as u32);
            vector.add(0x18).cast::<u32>().write((storage as usize as u32).wrapping_add(24));
        }
    }
    unsafe extern "C" fn copy_construct(destination: *mut u8, source: *const u8) {
        unsafe {
            COPY_CALLS.fetch_add(1, Ordering::SeqCst);
            destination.cast::<u32>().write(source.cast::<u32>().read());
            destination.add(4).cast::<u32>().write(source.add(4).cast::<u32>().read());
        }
    }

    #[test]
    fn grows_at_capacity_then_copies_and_advances() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PATH_OBJECT_VECTOR_PUSH_BACK, 0x1000,
        ) else { return };
        let vector = slab;
        let storage = unsafe { slab.add(0x100) };
        let record = unsafe { slab.add(0x200) };
        unsafe {
            EMPTY.store(0, Ordering::SeqCst);
            GROW_CALLS.store(0, Ordering::SeqCst);
            COPY_CALLS.store(0, Ordering::SeqCst);
            GROW_STORAGE.store(storage as usize, Ordering::SeqCst);
            vector.add(0x10).cast::<u32>().write(storage as usize as u32);
            vector.add(0x18).cast::<u32>().write(storage as usize as u32);
            vector.add(0x20).cast::<u32>().write(u32::MAX);
            record.cast::<u32>().write(0x1122_3344);
            record.add(4).cast::<u32>().write(0x5566_7788);
            record.add(8).cast::<u32>().write(0x99aa_bbcc);
            path_object_vector_push_back_with(vector, record, is_empty, grow, copy_construct);
            assert_eq!(GROW_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(COPY_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(storage.cast::<u32>().read(), 0x1122_3344);
            assert_eq!(storage.add(4).cast::<u32>().read(), 0x5566_7788);
            assert_eq!(storage.add(8).cast::<u32>().read(), 0x99aa_bbcc);
            assert_eq!(vector.add(0x10).cast::<u32>().read(), storage as usize as u32 + 12);
            assert_eq!(vector.add(0x20).cast::<u32>().read(), 0);
        }
    }

    #[test]
    fn empty_vector_grows_even_with_available_cursor() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PATH_OBJECT_VECTOR_PUSH_BACK_EMPTY, 0x1000,
        ) else { return };
        unsafe {
            EMPTY.store(1, Ordering::SeqCst);
            GROW_CALLS.store(0, Ordering::SeqCst);
            COPY_CALLS.store(0, Ordering::SeqCst);
            GROW_STORAGE.store(slab.add(0x100) as usize, Ordering::SeqCst);
            slab.add(0x10).cast::<u32>().write(slab.add(0x300) as usize as u32);
            slab.add(0x18).cast::<u32>().write(slab.add(0x400) as usize as u32);
            slab.add(0x20).cast::<u32>().write(7);
            slab.add(0x200).cast::<u32>().write(3);
            path_object_vector_push_back_with(slab, slab.add(0x200), is_empty, grow, copy_construct);
            assert_eq!(GROW_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(COPY_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(slab.add(0x20).cast::<u32>().read(), 8);
        }
    }
}
