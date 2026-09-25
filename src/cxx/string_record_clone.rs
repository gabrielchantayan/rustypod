//! Clone a target-layout four-word string record.

use core::ptr;

/// Target-layout source record: byte count, data pointer, an unused word, and
/// caller metadata. Pointer words remain `u32` so the field offsets stay ARM
/// offsets on 64-bit hosts.
pub type StringRecord = [u32; 4];

/// Direct-call boundaries not yet individually ported.
#[derive(Clone, Copy)]
pub struct StringRecordCloneOps {
    pub allocate: unsafe extern "C" fn() -> *mut StringRecord,
    pub assign: unsafe extern "C" fn(*mut StringRecord, *const u8, i32) -> bool,
    pub destroy: unsafe extern "C" fn(*mut StringRecord),
}

unsafe extern "C" fn missing_allocate() -> *mut StringRecord { ptr::null_mut() }
unsafe extern "C" fn missing_assign(_: *mut StringRecord, _: *const u8, _: i32) -> bool { false }
unsafe extern "C" fn missing_destroy(_: *mut StringRecord) {}

/// Default target boundary. The three concrete retail callees are unported;
/// returning allocation failure preserves the caller's failure result rather
/// than substituting a different allocator or string implementation.
pub const DEFAULT_STRING_RECORD_CLONE_OPS: StringRecordCloneOps = StringRecordCloneOps {
    allocate: missing_allocate,
    assign: missing_assign,
    destroy: missing_destroy,
};

pub static mut STRING_RECORD_CLONE_OPS: StringRecordCloneOps = DEFAULT_STRING_RECORD_CLONE_OPS;

#[inline(always)]
unsafe fn ops() -> StringRecordCloneOps {
    ptr::read_volatile(ptr::addr_of!(STRING_RECORD_CLONE_OPS))
}

/// string_record_clone — original: `FUN_0803a298` @ **0x0803a298** (80 bytes,
/// not Ghidra's 84). Raw `osos.dec` words establish the complete body from
/// `0x0803a298` through `b 0x0803a2b4` at `0x0803a2e8`; `0x0803a2ec` begins
/// the next function. It has **3 plain `bl` and 0 predicated `bl` calls**.
///
/// Allocates a four-word string record, assigns the source's data word with its
/// signed byte count, then copies source word +0xc into destination word +0xc.
/// Failed assignment destroys the new record; a null source or allocation
/// failure returns NULL. Deliberate deviation: the three unported direct
/// callees (allocate @ 0x0803a488, assign @ 0x0803a3cc, destroy @ 0x0803a2ec)
/// use an injectable boundary. The default fails closed because invoking ARM
/// addresses as host or Rust function pointers is invalid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_record_clone(source: *const StringRecord) -> *mut StringRecord {
    if source.is_null() {
        return ptr::null_mut();
    }
    let operations = ops();
    let destination = (operations.allocate)();
    if destination.is_null() {
        return ptr::null_mut();
    }
    let source_words = &*source;
    if (operations.assign)(destination, source_words[1] as usize as *const u8, source_words[0] as i32) {
        (*destination)[3] = source_words[3];
        destination
    } else {
        (operations.destroy)(destination);
        ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATION: StringRecord = [0; 4];
    static mut ALLOCATE_RETURNS_NULL: bool = false;
    static mut ASSIGN_SUCCEEDS: bool = true;
    static mut DESTROY_CALLS: u32 = 0;
    static mut ASSIGN_DATA: *const u8 = ptr::null();
    static mut ASSIGN_LEN: i32 = 0;

    unsafe extern "C" fn allocate() -> *mut StringRecord {
        if ALLOCATE_RETURNS_NULL { ptr::null_mut() } else { ptr::addr_of_mut!(ALLOCATION) }
    }
    unsafe extern "C" fn assign(_: *mut StringRecord, data: *const u8, len: i32) -> bool {
        ASSIGN_DATA = data;
        ASSIGN_LEN = len;
        ASSIGN_SUCCEEDS
    }
    unsafe extern "C" fn destroy(_: *mut StringRecord) { DESTROY_CALLS += 1; }

    #[test]
    fn clones_data_length_and_metadata_only_after_assignment() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::STRING_RECORD_CLONE, 4096) else { return; };
        unsafe {
            let source = slab.cast::<StringRecord>();
            let bytes = slab.add(64);
            bytes.copy_from_nonoverlapping(b"abc\0".as_ptr(), 4);
            *source = [3, bytes as usize as u32, 0xdead_beef, 0x1234_5678];
            ALLOCATION = [0xa5; 4]; ALLOCATE_RETURNS_NULL = false; ASSIGN_SUCCEEDS = true;
            DESTROY_CALLS = 0; ASSIGN_DATA = ptr::null(); ASSIGN_LEN = 0;
            let saved = STRING_RECORD_CLONE_OPS;
            STRING_RECORD_CLONE_OPS = StringRecordCloneOps { allocate, assign, destroy };
            let result = string_record_clone(source);
            STRING_RECORD_CLONE_OPS = saved;
            assert_eq!(result, ptr::addr_of_mut!(ALLOCATION));
            assert_eq!(ASSIGN_DATA, bytes);
            assert_eq!(ASSIGN_LEN, 3);
            assert_eq!(ALLOCATION[3], 0x1234_5678);
            assert_eq!(ALLOCATION[0], 0xa5, "the caller does not copy other words");
            assert_eq!(DESTROY_CALLS, 0);
        }
    }
    #[test]
    fn rejects_null_or_failed_allocations_without_assignment() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = STRING_RECORD_CLONE_OPS;
            STRING_RECORD_CLONE_OPS = StringRecordCloneOps { allocate, assign, destroy };
            ASSIGN_LEN = 99; DESTROY_CALLS = 0;
            assert!(string_record_clone(ptr::null()).is_null());
            assert_eq!(ASSIGN_LEN, 99);
            ALLOCATE_RETURNS_NULL = true;
            assert!(string_record_clone(ptr::addr_of!(ALLOCATION)).is_null());
            assert_eq!(DESTROY_CALLS, 0);
            ALLOCATE_RETURNS_NULL = false;
            STRING_RECORD_CLONE_OPS = saved;
        }
    }
    #[test]
    fn destroys_fresh_record_after_assignment_failure() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = STRING_RECORD_CLONE_OPS;
            STRING_RECORD_CLONE_OPS = StringRecordCloneOps { allocate, assign, destroy };
            ALLOCATE_RETURNS_NULL = false; ASSIGN_SUCCEEDS = false; DESTROY_CALLS = 0;
            let source = [u32::MAX, 0, 0, 0x88];
            assert!(string_record_clone(&source).is_null());
            assert_eq!(ASSIGN_LEN, -1, "the signed length is passed unchanged");
            assert_eq!(DESTROY_CALLS, 1);
            ASSIGN_SUCCEEDS = true;
            STRING_RECORD_CLONE_OPS = saved;
        }
    }
}
