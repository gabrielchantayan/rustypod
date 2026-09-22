//! Appends one byte to an embedded byte vector.
//!
//! `byte_vector_owner_push_back` — `FUN_08268210` @ **0x08268210**
//! (**56 bytes exactly**, `0x08268210..0x08268247`; the separately linked
//! constructor at `0x08268248` is the next real function). Raw A32 decoding
//! finds one plain `bl` (to `0x083e1188`) and no predicated `bl` instructions.
//!
//! # Algorithm
//!
//! The owner embeds a three-word `std::vector<unsigned char>` at +0x14. When
//! `end != capacity`, it advances `end` then conditionally writes the low byte
//! of the argument at the old end. Otherwise it invokes the verified
//! `0x083e1188` vector insertion ABI with `(vector, end, &byte)`.
//!
//! # Deliberate deviations
//!
//! The growth helper's allocation and relocation protocol remains retailOS;
//! target builds call its verified address and host builds use a replaceable
//! seam. The owner has no recovered layout, so the embedded vector is reached
//! through its target byte offset rather than a host-layout-dependent struct.

use crate::cxx::string_byte_vector_record::ByteVector;

const BYTE_VECTOR_OFFSET: usize = 0x14;
const BYTE_VECTOR_INSERT_ADDRESS: usize = 0x083e_1188;

pub type ByteVectorInsert = unsafe extern "C" fn(*mut ByteVector, *mut u8, *const u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_byte_vector_insert(vector: *mut ByteVector, position: *mut u8, byte: *const u8) {
    unsafe { core::mem::transmute::<usize, ByteVectorInsert>(BYTE_VECTOR_INSERT_ADDRESS)(vector, position, byte) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_byte_vector_insert(_: *mut ByteVector, _: *mut u8, _: *const u8) {
    panic!("byte_vector_owner_push_back requires retail vector insertion 0x083e1188")
}

#[cfg(target_os = "none")]
pub static mut BYTE_VECTOR_INSERT: ByteVectorInsert = retail_byte_vector_insert;
#[cfg(not(target_os = "none"))]
pub static mut BYTE_VECTOR_INSERT: ByteVectorInsert = missing_byte_vector_insert;

#[inline(always)]
fn byte_vector_insert() -> ByteVectorInsert {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BYTE_VECTOR_INSERT)) }
}

/// Appends the low byte of `value` to the owner's embedded byte vector.
///
/// # Safety
///
/// `owner + 0x14` must be a valid target-width [`ByteVector`]. The retail
/// routine has no NULL, capacity, or backing-storage validity guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_vector_owner_push_back(owner: *mut u8, value: u32) {
    let vector = unsafe { owner.add(BYTE_VECTOR_OFFSET).cast::<ByteVector>() };
    let end = unsafe { (*vector).end as *mut u8 };
    if end == unsafe { (*vector).capacity as *mut u8 } {
        let byte = value as u8;
        unsafe { byte_vector_insert()(vector, end, core::ptr::addr_of!(byte)) };
    } else {
        unsafe {
            (*vector).end = end.add(1) as u32;
            if !end.is_null() {
                end.write(value as u8);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INSERT_CALL: Option<(*mut ByteVector, *mut u8, u8)> = None;

    unsafe extern "C" fn record_insert(vector: *mut ByteVector, position: *mut u8, byte: *const u8) {
        unsafe { INSERT_CALL = Some((vector, position, byte.read())) };
    }

    #[test]
    fn appends_low_byte_and_advances_end_when_capacity_remains() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::BYTE_VECTOR_OWNER_PUSH_BACK, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/byte_vector_owner_push_back"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let owner = slab.add(0x100);
            let storage = slab.add(0x200);
            let vector = owner.add(BYTE_VECTOR_OFFSET).cast::<ByteVector>();
            vector.write(ByteVector { begin: storage as u32, end: storage as u32, capacity: storage.add(2) as u32 });
            byte_vector_owner_push_back(owner, 0xfeed_12a5);
            assert_eq!((*vector).end, storage.add(1) as u32);
            assert_eq!(storage.read(), 0xa5);
            assert!(INSERT_CALL.is_none());
        }
    }

    #[test]
    fn delegates_full_vector_with_end_and_stack_byte() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::BYTE_VECTOR_OWNER_PUSH_BACK, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/byte_vector_owner_push_back"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let owner = slab.add(0x100);
            let end = slab.add(0x200);
            let vector = owner.add(BYTE_VECTOR_OFFSET).cast::<ByteVector>();
            vector.write(ByteVector { begin: slab.add(0x180) as u32, end: end as u32, capacity: end as u32 });
            addr_of_mut!(INSERT_CALL).write(None);
            addr_of_mut!(BYTE_VECTOR_INSERT).write(record_insert);
            byte_vector_owner_push_back(owner, 0xffff_ff34);
            let (called_vector, position, byte) = INSERT_CALL.unwrap();
            assert_eq!(called_vector, vector);
            assert_eq!(position, end);
            assert_eq!(byte, 0x34);
            assert_eq!((*vector).end, end as u32);
            addr_of_mut!(BYTE_VECTOR_INSERT).write(missing_byte_vector_insert);
            let _ = addr_of!(BYTE_VECTOR_INSERT);
        }
    }
}
