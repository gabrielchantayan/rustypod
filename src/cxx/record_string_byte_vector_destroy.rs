//! Destructor for the 32-byte record whose copy assignment is
//! [`record_string_byte_vector_assign`](super::string_byte_vector_record::record_string_byte_vector_assign).
//!
//! The target layout is a `StringObject`, an opaque word, and a three-word
//! `std::vector<unsigned char>` representation. The element walk in retailOS
//! has no body because byte elements have trivial destructors.

use crate::cxx::string_byte_vector_record::StringByteVectorRecord;
use crate::cxx::string_object::string_object_destroy;
use crate::heap::veneers::cxx_array_dealloc;

/// record_string_byte_vector_destroy — original: `FUN_082678d4` @
/// `0x082678d4` (**64 bytes**, `0x082678d4..0x08267913`; the next separately
/// linked function begins at `0x08267914`). **3 direct inbound `bl` call
/// sites**, all unconditional; no predicated inbound calls. The body has one
/// unconditional `bl`, to `cxx_array_dealloc` @ `0x08266f2c`, and a tail
/// branch to `string_object_destroy` @ `0x08277484`.
///
/// The byte vector at target offsets +12/+16/+20 has trivial elements, so the
/// retail element walk has no observable body. It releases the backing span
/// through `cxx_array_dealloc(begin, capacity - begin, 0)`, then tail-destroys
/// the embedded StringObject and returns `this`.
///
/// Deliberate deviation: the dead element walk is omitted. Named fields, not
/// host byte offsets, preserve the target's 32-bit member order when
/// `StringObject` pointers widen on host tests.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_string_byte_vector_destroy(
    this: *mut StringByteVectorRecord,
) -> *mut StringByteVectorRecord {
    unsafe { record_string_byte_vector_destroy_with(this, cxx_array_dealloc, string_object_destroy) }
}

#[inline(always)]
unsafe fn record_string_byte_vector_destroy_with(
    this: *mut StringByteVectorRecord,
    dealloc: unsafe extern "C" fn(*mut u8, usize, usize),
    destroy_string: unsafe extern "C" fn(*mut crate::cxx::string_object::StringObject) -> *mut crate::cxx::string_object::StringObject,
) -> *mut StringByteVectorRecord {
    let bytes = core::ptr::addr_of_mut!((*this).bytes);
    let begin = (*bytes).begin;
    dealloc(begin as usize as *mut u8, (*bytes).capacity.wrapping_sub(begin) as usize, 0);
    destroy_string(core::ptr::addr_of_mut!((*this).string)).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_byte_vector_record::ByteVector;
    use crate::cxx::string_object::StringObject;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut DEALLOC_CALL: Option<(*mut u8, usize, usize)> = None;
    static mut DESTROY_CALL: *mut StringObject = core::ptr::null_mut();

    unsafe extern "C" fn recording_dealloc(ptr: *mut u8, count: usize, elem_size: usize) {
        DEALLOC_CALL = Some((ptr, count, elem_size));
    }

    unsafe extern "C" fn recording_destroy(string: *mut StringObject) -> *mut StringObject {
        DESTROY_CALL = string;
        string
    }

    #[test]
    fn destroys_an_empty_vector_and_returns_its_record() {
        let _guard = LOCK.lock();
        let mut record = StringByteVectorRecord {
            string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() },
            value: 0x1122_3344,
            bytes: ByteVector { begin: 0x1000, end: 0x1000, capacity: 0x1010 },
            first_flag: 0xaa,
            second_flag: 0x55,
            trailing: 0x5566_7788,
        };

        unsafe {
            DEALLOC_CALL = None;
            DESTROY_CALL = core::ptr::null_mut();
            let returned = record_string_byte_vector_destroy_with(
                &mut record,
                recording_dealloc,
                recording_destroy,
            );
            assert!(core::ptr::eq(returned, &mut record));
            assert_eq!(DEALLOC_CALL, Some((0x1000 as *mut u8, 16, 0)));
            assert!(core::ptr::eq(DESTROY_CALL, &mut record.string));
            assert_eq!(record.value, 0x1122_3344);
            assert_eq!(record.bytes.end, 0x1000);
        }
    }

    #[test]
    fn wraps_the_target_width_capacity_subtraction() {
        let _guard = LOCK.lock();
        let mut record = StringByteVectorRecord {
            string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() },
            value: 0,
            bytes: ByteVector { begin: 0xffff_fffe, end: 0, capacity: 1 },
            first_flag: 0,
            second_flag: 0,
            trailing: 0,
        };

        unsafe {
            DEALLOC_CALL = None;
            let _ = record_string_byte_vector_destroy_with(
                &mut record,
                recording_dealloc,
                recording_destroy,
            );
            assert_eq!(DEALLOC_CALL, Some((0xffff_fffeusize as *mut u8, 3, 0)));
        }
    }
}
