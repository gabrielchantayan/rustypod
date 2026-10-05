//! String/vector key constructor — `FUN_08197ab8` @ `0x08197ab8`.
//!
//! True extent: 216 bytes (212 instruction bytes and a four-byte literal),
//! ending at the next prologue at `0x08197b90`. Raw A32 decoding verifies nine
//! outbound plain BLs, zero predicated BLs, and two inbound plain BLs.
//! Copies the primary C string into a COW representation with capacity
//! max(length, 32), or uses the shared empty representation. Clears the
//! entry-vector bounds and writes the low flag byte. If the secondary string
//! is nonempty, constructs a temporary string/vector record, assigns both
//! members, appends it to the entry vector, and destroys the temporary.
//! Deliberate deviations: host pointer fields widen via repr(C); dead r2/r3
//! spills are omitted. Three unported composite operations retain verified
//! retail addresses and ABIs rather than a guessed container implementation.
//! The existing representation allocator's NULL-return deviation is inherited;
//! allocation success remains a precondition here, as in the retail constructor.

use core::ptr;
use super::string::{cxx_string_assign_cstr, cxx_string_release, cxx_string_rep_create,
    empty_rep, rep_data};
use super::string_vector_destruct::{CxxStringVector, cxx_string_vector_destruct};

#[repr(C)]
pub struct StringVectorRecord {
    pub string: *mut u8,
    pub vector: CxxStringVector,
}

#[repr(C)]
pub struct StringVectorKey {
    pub record: StringVectorRecord,
    pub flag: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 16] = [0; core::mem::offset_of!(StringVectorKey, flag)];

pub type RecordInitialize = unsafe extern "C" fn(*mut StringVectorRecord);
pub type VectorAssign = unsafe extern "C" fn(*mut CxxStringVector, *const CxxStringVector);
pub type RecordAppend = unsafe extern "C" fn(*mut CxxStringVector, *const StringVectorRecord);

#[derive(Clone, Copy)]
pub struct StringVectorKeyConstructOps {
    pub initialize: RecordInitialize,
    pub assign_vector: VectorAssign,
    pub append: RecordAppend,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn initialize(record: *mut StringVectorRecord) {
    core::mem::transmute::<usize, RecordInitialize>(0x0819_7a74)(record);
}
#[cfg(target_os = "none")]
unsafe extern "C" fn assign_vector(destination: *mut CxxStringVector, source: *const CxxStringVector) {
    core::mem::transmute::<usize, VectorAssign>(0x083e_5bb8)(destination, source);
}
#[cfg(target_os = "none")]
unsafe extern "C" fn append(destination: *mut CxxStringVector, record: *const StringVectorRecord) {
    core::mem::transmute::<usize, RecordAppend>(0x083e_23b8)(destination, record);
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn initialize(_: *mut StringVectorRecord) { panic!("install key record initializer fixture") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn assign_vector(_: *mut CxxStringVector, _: *const CxxStringVector) { panic!("install key vector assignment fixture") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn append(_: *mut CxxStringVector, _: *const StringVectorRecord) { panic!("install key record append fixture") }

pub const DEFAULT_STRING_VECTOR_KEY_CONSTRUCT_OPS: StringVectorKeyConstructOps = StringVectorKeyConstructOps {
    initialize, assign_vector, append,
};
pub static mut STRING_VECTOR_KEY_CONSTRUCT_OPS: StringVectorKeyConstructOps = DEFAULT_STRING_VECTOR_KEY_CONSTRUCT_OPS;

/// # Safety
/// Destination is aligned writable storage; both strings are NUL-terminated.
/// A nonempty secondary string requires a valid source vector and installed
/// composite operations on hosts. Allocations must succeed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_vector_key_construct(
    destination: *mut StringVectorKey,
    primary: *const u8,
    secondary: *const u8,
    source_vector: *const CxxStringVector,
    flag: u32,
) -> *mut StringVectorKey {
    let length = crate::libc::strlen::strlen(primary) as u32;
    let rep = if length == 0 { empty_rep() } else {
        cxx_string_rep_create(destination.cast(), core::cmp::max(length, 32), length)
    };
    let data = rep_data(rep);
    ptr::addr_of_mut!((*destination).record.string).write(data);
    crate::libc::rt_memcpy::__rt_memcpy(data, primary, length as usize);
    ptr::addr_of_mut!((*destination).record.vector).write(CxxStringVector {
        begin: ptr::null_mut(), end: ptr::null_mut(), capacity: ptr::null_mut(),
    });
    ptr::addr_of_mut!((*destination).flag).write(flag as u8);
    if secondary.read() != 0 {
        let ops = ptr::read_volatile(ptr::addr_of!(STRING_VECTOR_KEY_CONSTRUCT_OPS));
        let mut temporary = core::mem::MaybeUninit::<StringVectorRecord>::uninit();
        let record = temporary.as_mut_ptr();
        (ops.initialize)(record);
        cxx_string_assign_cstr(ptr::addr_of_mut!((*record).string), secondary);
        (ops.assign_vector)(ptr::addr_of_mut!((*record).vector), source_vector);
        (ops.append)(ptr::addr_of_mut!((*destination).record.vector), record);
        let vector = cxx_string_vector_destruct(ptr::addr_of_mut!((*record).vector));
        let record = vector.cast::<u8>().sub(core::mem::offset_of!(StringVectorRecord, vector)).cast::<StringVectorRecord>();
        cxx_string_release(ptr::addr_of_mut!((*record).string));
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};

    #[test]
    fn primary_capacity_boundary_copy_terminator_and_untouched_padding() {
        let _heap = mock_heap();
        for length in [1usize, 31, 32, 33, 64] {
            let mut allocation = [0xa5u32; 32];
            let mut source = [b'x'; 68];
            source[length] = 0;
            let mut storage = [usize::MAX / 255 * 0xcc; 8];
            let destination = storage.as_mut_ptr().cast::<StringVectorKey>();
            unsafe {
                set_alloc_ret(allocation.as_mut_ptr().cast());
                assert_eq!(string_vector_key_construct(destination, source.as_ptr(), b"\0".as_ptr(), ptr::null(), 0x1234_56a7), destination);
                let data = (*destination).record.string;
                let rep = super::super::string::data_rep(data);
                assert_eq!((*rep).capacity, length.max(32) as u32);
                assert_eq!((*rep).length, length as u32);
                assert_eq!((*rep).refcount, 0);
                assert_eq!(core::slice::from_raw_parts(data, length), &source[..length]);
                assert_eq!(data.add(length).read(), 0);
                assert!((*destination).record.vector.begin.is_null());
                assert!((*destination).record.vector.end.is_null());
                assert!((*destination).record.vector.capacity.is_null());
                assert_eq!((*destination).flag, 0xa7);
                let flag_offset = core::mem::offset_of!(StringVectorKey, flag);
                assert!(core::slice::from_raw_parts(destination.cast::<u8>().add(flag_offset + 1), core::mem::size_of_val(&storage) - flag_offset - 1).iter().all(|&b| b == 0xcc));
            }
            assert_eq!(alloc_log().1, length.max(32) + 14);
        }
    }

    #[test]
    fn empty_primary_uses_shared_rep_and_empty_secondary_never_reads_vector() {
        let _heap = mock_heap();
        let mut storage = [usize::MAX / 255 * 0xcc; 8];
        unsafe {
            let destination = storage.as_mut_ptr().cast::<StringVectorKey>();
            string_vector_key_construct(destination, b"\0".as_ptr(), b"\0".as_ptr(), ptr::null(), 0);
            assert_eq!((*destination).record.string, super::super::string::empty_rep_data());
            assert_eq!((*destination).record.string.read(), 0);
            assert!((*destination).record.vector.begin.is_null());
            assert!((*destination).record.vector.end.is_null());
            assert!((*destination).record.vector.capacity.is_null());
            assert_eq!((*destination).flag, 0);
        }
        assert_eq!(alloc_log().0, 0);
    }
}
