//! Accessor for an unidentified UI object's state word.

/// object_state_word — original: `FUN_08055e80` @ `0x08055e80` (12 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055e80_FUN_08055e80.c`.
/// The ARM leaf loads and returns the little-endian 32-bit state word at
/// offset `0xe38` in an otherwise unidentified UI object. It performs no
/// null or alignment checks, matching the original `ldr` ABI.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_state_word(object: *const u8) -> u32 {
    (object.add(0xe38) as *const u32).read()
}

/// The UI sequence identifier state (original global @ `0x089c_fcc4`).
///
/// The firmware reaches this runtime-initialized word through the literal at
/// `0x0805_5ecc`; this static models that target-side state.
pub static mut SEQUENCE_ID: u32 = 0;

/// sequence_id_next — original: `FUN_08055eb8` @ `0x08055eb8` (16 bytes).
///
/// Sources: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055eb8_FUN_08055eb8.c`
/// and `decomp/osos.asm` @ `0x08055eb8..0x08055ec8`. The decompilation
/// incorrectly declares `void`; the ARM leaf leaves the loaded word in `r0`.
/// It loads the sequence word at `0x089c_fcc4` through its `0x0805_5ecc`
/// literal, stores that word plus one with wrapping 32-bit arithmetic, and
/// returns the pre-increment value. The runtime global is modeled by
/// [`SEQUENCE_ID`] rather than its fixed device address.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sequence_id_next() -> u32 {
    let state = core::ptr::addr_of_mut!(SEQUENCE_ID);
    let sequence_id = core::ptr::read_volatile(state);
    core::ptr::write_volatile(state, sequence_id.wrapping_add(1));
    sequence_id
}

/// The three words inspected by [`indexed_object_offset`], followed by the
/// storage word consumed by its unported base-address callee.
///
/// Call sites at 0x08066bb8, 0x080e2d70, and 0x080e2dc8 pass this header and
/// use a one-based index to address fixed-size records. The callee at
/// 0x080aa828 verifies the same tag and reads `storage` at byte offset 24.
#[repr(C)]
pub struct IndexedObject {
    /// Fixed object-format tag: the literal at 0x08055f20 is `0x6172_6179`.
    pub type_tag: u32,
    /// Byte stride of one stored record.
    pub element_size: u32,
    /// Number of addressable records.
    pub element_count: u32,
    /// Header words not inspected by this helper.
    pub reserved: [u32; 3],
    /// Storage pointer read by the unported 0x080aa828 base-address helper.
    pub storage: *mut u8,
}

/// Object tag loaded from the literal pool at 0x08055f20.
pub const INDEXED_OBJECT_TAG: u32 = 0x6172_6179;

type IndexedObjectStorageBase = unsafe extern "C" fn(*const IndexedObject) -> *mut u8;

/// Calls the stock object-storage-base helper, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x080aa828. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address.
unsafe extern "C" fn firmware_indexed_object_storage_base(
    object: *const IndexedObject,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let storage_base: IndexedObjectStorageBase =
            core::mem::transmute(0x080a_a828usize);
        storage_base(object)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = object;
        core::ptr::null_mut()
    }
}

/// Narrow boundary for the unported 0x080aa828 dependency.
static mut INDEXED_OBJECT_STORAGE_BASE: IndexedObjectStorageBase =
    firmware_indexed_object_storage_base;

#[inline(always)]
unsafe fn indexed_object_storage_base() -> IndexedObjectStorageBase {
    core::ptr::read_volatile(core::ptr::addr_of!(INDEXED_OBJECT_STORAGE_BASE))
}

/// indexed_object_offset — original: `FUN_08055ed0` @ `0x08055ed0` (80
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055ed0_FUN_08055ed0.c`;
/// assembly: `decomp/osos.asm` @ `0x08055ed0..0x08055f1c`.
///
/// Addresses one-based fixed-size records in an [`IndexedObject`]. It first
/// requires the literal [`INDEXED_OBJECT_TAG`], a nonzero index, and
/// `index <= element_count`; only then does it call retailOS helper
/// 0x080aa828 for the storage base and add `element_size * (index - 1)`.
///
/// # Safety
///
/// `object` must be readable as an aligned [`IndexedObject`]. Like the ARM
/// `ldr` at entry, this function has no null or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_object_offset(
    object: *const IndexedObject,
    index: u32,
) -> *mut u8 {
    if (*object).type_tag != INDEXED_OBJECT_TAG
        || index == 0
        || index > (*object).element_count
    {
        return core::ptr::null_mut();
    }

    let storage_base = indexed_object_storage_base()(object);
    storage_base.wrapping_add(
        (*object)
            .element_size
            .wrapping_mul(index.wrapping_sub(1)) as usize,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::{Mutex, MutexGuard};

    static SEQUENCE_ID_LOCK: Mutex<()> = Mutex::new(());
    static INDEXED_OBJECT_STORAGE_BASE_LOCK: Mutex<()> = Mutex::new(());
    static mut STORAGE_BASE_CALLS: u32 = 0;
    static mut STORAGE_BASE_OBJECT: usize = 0;
    static mut MOCK_STORAGE_BASE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_storage_base(object: *const IndexedObject) -> *mut u8 {
        STORAGE_BASE_CALLS += 1;
        STORAGE_BASE_OBJECT = object as usize;
        MOCK_STORAGE_BASE
    }

    /// Restores the stock-call boundary before another test uses it.
    struct StorageBaseReset;

    impl Drop for StorageBaseReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(INDEXED_OBJECT_STORAGE_BASE)
                    .write(firmware_indexed_object_storage_base);
            }
        }
    }

    fn install_recording_storage_base(storage_base: *mut u8) -> MutexGuard<'static, ()> {
        let guard = INDEXED_OBJECT_STORAGE_BASE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            STORAGE_BASE_CALLS = 0;
            STORAGE_BASE_OBJECT = 0;
            MOCK_STORAGE_BASE = storage_base;
            core::ptr::addr_of_mut!(INDEXED_OBJECT_STORAGE_BASE).write(recording_storage_base);
        }
        guard
    }

    fn indexed_object(
        type_tag: u32,
        element_size: u32,
        element_count: u32,
    ) -> IndexedObject {
        IndexedObject {
            type_tag,
            element_size,
            element_count,
            reserved: [0; 3],
            storage: core::ptr::null_mut(),
        }
    }

    fn seed_sequence_id(value: u32) {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SEQUENCE_ID), value);
        }
    }

    fn sequence_id() -> u32 {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SEQUENCE_ID)) }
    }

    #[test]
    fn returns_the_word_at_offset_e38() {
        let mut object = [0u8; 0xe3c];
        object[0xe38..0xe3c].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x89ab_cdef);
    }

    #[test]
    fn ignores_adjacent_object_bytes() {
        let mut object = [0xa5u8; 0xe40];
        object[0xe34..0xe38].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        object[0xe38..0xe3c].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        object[0xe3c..0xe40].copy_from_slice(&0x99aa_bbccu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x5566_7788);
    }

    #[test]
    fn returns_then_advances_the_sequence_state() {
        let _guard = SEQUENCE_ID_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        for initial in [0, 1, 0x2468_ace0, 0xffff_fffe] {
            seed_sequence_id(initial);
            assert_eq!(unsafe { sequence_id_next() }, initial);
            assert_eq!(sequence_id(), initial.wrapping_add(1));
        }
    }

    #[test]
    fn wraps_after_returning_the_maximum_sequence_id() {
        let _guard = SEQUENCE_ID_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        seed_sequence_id(u32::MAX);
        assert_eq!(unsafe { sequence_id_next() }, u32::MAX);
        assert_eq!(sequence_id(), 0);
        assert_eq!(unsafe { sequence_id_next() }, 0);
        assert_eq!(sequence_id(), 1);
    }
    #[test]
    fn wrong_type_tag_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG ^ 1, 4, 1);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 1) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn zero_index_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 4, 1);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 0) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn index_above_count_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 4, 2);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 3) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn valid_one_based_indices_call_storage_base_and_scale_by_stride() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 12, 3);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 1) },
            storage.as_mut_ptr(),
            "the first one-based record begins at the base"
        );
        assert_eq!(
            unsafe { indexed_object_offset(&object, 3) },
            unsafe { storage.as_mut_ptr().add(24) },
            "the upper inclusive index uses stride * (index - 1)"
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 2);
        assert_eq!(unsafe { STORAGE_BASE_OBJECT }, &object as *const IndexedObject as usize);
    }
}
