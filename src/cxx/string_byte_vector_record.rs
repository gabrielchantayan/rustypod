//! Copy assignment for an unidentified 32-byte record used by the 0x083eXXXX
//! vector helpers.
//!
//! Its target layout is a [`StringObject`], an opaque word, a three-word byte
//! vector, two byte flags, and a final opaque word. The vector's element
//! ownership protocol remains in retailOS.

use crate::cxx::string_object::{string_object_assign, StringObject};

/// Three target-width pointers comprising the record's byte vector at +0x0c.
#[repr(C)]
pub struct ByteVector {
    pub begin: u32,
    pub end: u32,
    pub capacity: u32,
}

/// The record assigned by `record_string_byte_vector_assign`.
///
/// The target is 32 bytes. `StringObject` is widened on 64-bit hosts, so the
/// named fields preserve target member semantics rather than host byte offsets.
#[repr(C)]
pub struct StringByteVectorRecord {
    pub string: StringObject,
    pub value: u32,
    pub bytes: ByteVector,
    pub first_flag: u8,
    pub second_flag: u8,
    pub trailing: u32,
}

unsafe extern "C" fn byte_vector_assign_stub(
    this: *mut ByteVector,
    source: *const ByteVector,
) -> *mut ByteVector {
    if this != source as *mut ByteVector {
        // The retail helper owns element copies, allocation, and release.
    }
    this
}

/// Host-model boundary for the unported `std::vector<unsigned char>` copy
/// assignment at `FUN_083e6234`. A later port replaces this slot without
/// changing the record assignment's call order.
pub static mut BYTE_VECTOR_ASSIGN: unsafe extern "C" fn(
    *mut ByteVector,
    *const ByteVector,
) -> *mut ByteVector = byte_vector_assign_stub;

#[inline(always)]
unsafe fn byte_vector_assign_op() -> unsafe extern "C" fn(*mut ByteVector, *const ByteVector) -> *mut ByteVector {
    core::ptr::read_volatile(core::ptr::addr_of!(BYTE_VECTOR_ASSIGN))
}

/// record_string_byte_vector_assign — original: `FUN_08267914` @ `0x08267914`
/// (68 bytes; the next separately linked function starts at `0x08267958`).
/// **4 direct `bl` call sites** verified by decoding every ARM `B`/`BL` word
/// in `osos.dec`: `0x08268034`, `0x083e3f4c`, `0x083e3f64`, and
/// `0x083e3fb0`; all four are unconditional, with no predicated calls. The
/// body itself contains two unconditional calls: `string_object_assign` and
/// the byte-vector assignment helper.
/// Assigns the embedded StringObject, copies the word at +8, assigns the
/// byte vector at +12, copies both byte flags and the final word, then returns
/// `this`. The StringObject's address-based self-assignment guard does not
/// suppress the remaining field assignments.
///
/// Deliberate deviation: `FUN_083e6234` is unported, so its vector ownership
/// protocol is an injectable [`BYTE_VECTOR_ASSIGN`] boundary on host and
/// target instead of a direct retailOS call. Named fields account for widened
/// host pointers; target ARM offsets remain exactly +8, +12, +24, +25, and
/// +28.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_string_byte_vector_assign(
    this: *mut StringByteVectorRecord,
    source: *const StringByteVectorRecord,
) -> *mut StringByteVectorRecord {
    string_object_assign(
        core::ptr::addr_of_mut!((*this).string),
        core::ptr::addr_of!((*source).string),
    );
    (*this).value = (*source).value;
    byte_vector_assign_op()(
        core::ptr::addr_of_mut!((*this).bytes),
        core::ptr::addr_of!((*source).bytes),
    );
    (*this).first_flag = (*source).first_flag;
    (*this).second_flag = (*source).second_flag;
    (*this).trailing = (*source).trailing;
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::StringObject;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut VECTOR_CALL: Option<(*mut ByteVector, *const ByteVector)> = None;

    unsafe extern "C" fn recording_vector_assign(
        this: *mut ByteVector,
        source: *const ByteVector,
    ) -> *mut ByteVector {
        VECTOR_CALL = Some((this, source));
        this
    }

    #[test]
    fn assigns_every_non_string_member_after_both_nested_assignments() {
        let _guard = LOCK.lock();
        let source = StringByteVectorRecord {
            string: StringObject { vtable: core::ptr::null(), payload: b"x\0".as_ptr() as *mut u8 },
            value: 0x1122_3344,
            bytes: ByteVector { begin: 1, end: 4, capacity: 8 },
            first_flag: 0xaa,
            second_flag: 0x55,
            trailing: 0x5566_7788,
        };
        let mut destination = StringByteVectorRecord {
            string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() },
            value: 0,
            bytes: ByteVector { begin: 9, end: 9, capacity: 9 },
            first_flag: 0,
            second_flag: 0,
            trailing: 0,
        };
        unsafe {
            core::ptr::addr_of_mut!(VECTOR_CALL).write(None);
            core::ptr::addr_of_mut!(BYTE_VECTOR_ASSIGN).write(recording_vector_assign);
            let returned = record_string_byte_vector_assign(&mut destination, &source);
            assert!(core::ptr::eq(returned, &mut destination));
            assert_eq!(destination.value, source.value);
            assert_eq!(destination.first_flag, source.first_flag);
            assert_eq!(destination.second_flag, source.second_flag);
            assert_eq!(destination.trailing, source.trailing);
            let (called_destination, called_source) = VECTOR_CALL.unwrap();
            assert!(core::ptr::eq(called_destination, &mut destination.bytes));
            assert!(core::ptr::eq(called_source, &source.bytes));
            core::ptr::addr_of_mut!(BYTE_VECTOR_ASSIGN).write(byte_vector_assign_stub);
        }
    }

    #[test]
    fn self_assignment_still_calls_vector_assignment_and_returns_this() {
        let _guard = LOCK.lock();
        let mut record = StringByteVectorRecord {
            string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() },
            value: 7,
            bytes: ByteVector { begin: 2, end: 3, capacity: 4 },
            first_flag: 1,
            second_flag: 2,
            trailing: 3,
        };
        unsafe {
            core::ptr::addr_of_mut!(VECTOR_CALL).write(None);
            core::ptr::addr_of_mut!(BYTE_VECTOR_ASSIGN).write(recording_vector_assign);
            let returned = record_string_byte_vector_assign(&mut record, &record);
            assert!(core::ptr::eq(returned, &mut record));
            let (called_destination, called_source) = VECTOR_CALL.unwrap();
            assert!(core::ptr::eq(called_destination, &mut record.bytes));
            assert!(core::ptr::eq(called_source, &record.bytes));
            core::ptr::addr_of_mut!(BYTE_VECTOR_ASSIGN).write(byte_vector_assign_stub);
        }
    }
}
