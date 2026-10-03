//! `byte_vector_owner8_push_back` — `FUN_082681d8` @ **0x082681d8**.
//! True extent: 56 bytes, 0x082681d8..0x08268210 (exclusive); the next
//! separately linked append wrapper starts at 0x08268210. Raw A32 has one
//! plain internal BL to 0x083e40bc and no predicated internal BL. Whole-image
//! decoding finds one plain inbound BL at 0x0820ffd8 and one BLNE at 0x08210028.
//!
//! Algorithm: the owner embeds a three-word byte vector at +8. If end differs
//! from capacity, advance end by one, then store the low byte of value at the
//! old end unless it is NULL. Otherwise insert at end through 0x083e40bc,
//! passing the address of the complete saved value (the helper reads one byte).
//!
//! Deliberate deviations: allocation/relocation remain in retailOS through
//! a host-replaceable seam. Unknown owner layout uses target byte offsets;
//! ByteVector retains u32 pointer fields on hosts. Wrapping integer arithmetic
//! preserves the ARM increment even for the guarded NULL-end case.

use crate::cxx::string_byte_vector_record::ByteVector;

pub type Owner8ByteInsert = unsafe extern "C" fn(*mut ByteVector, *mut u8, *const u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_insert(vector: *mut ByteVector, position: *mut u8, value: *const u32) {
    unsafe { core::mem::transmute::<usize, Owner8ByteInsert>(0x083e_40bc)(vector, position, value) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_insert(_: *mut ByteVector, _: *mut u8, _: *const u32) {
    panic!("byte_vector_owner8_push_back requires retail insertion 0x083e40bc")
}

#[cfg(target_os = "none")]
pub static mut OWNER8_BYTE_INSERT: Owner8ByteInsert = retail_insert;
#[cfg(not(target_os = "none"))]
pub static mut OWNER8_BYTE_INSERT: Owner8ByteInsert = missing_insert;

/// Appends the low byte of value to the owner's embedded vector.
///
/// # Safety
/// owner+8 must point to an aligned, writable ByteVector with valid backing
/// storage or a descriptor accepted by the retail insertion helper.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_vector_owner8_push_back(owner: *mut u8, value: u32) {
    let vector = unsafe { owner.add(8).cast::<ByteVector>() };
    let end = unsafe { (*vector).end };
    if end == unsafe { (*vector).capacity } {
        let insert = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OWNER8_BYTE_INSERT)) };
        unsafe { insert(vector, end as *mut u8, core::ptr::addr_of!(value)) };
    } else {
        unsafe {
            (*vector).end = end.wrapping_add(1);
            if end != 0 {
                (end as *mut u8).write(value as u8);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    // Models the observable successful growth transition, rather than merely
    // recording forwarded arguments: the caller must leave the new end intact.
    unsafe extern "C" fn grow(vector: *mut ByteVector, position: *mut u8, value: *const u32) {
        unsafe {
            assert_eq!(position as u32, (*vector).end);
            assert_eq!((*vector).end, (*vector).capacity);
            let storage = vector.cast::<u8>().add(0x100);
            let len = (*vector).end.wrapping_sub((*vector).begin) as usize;
            if len != 0 {
                core::ptr::copy_nonoverlapping((*vector).begin as *const u8, storage, len);
            }
            storage.add(len).write(value.cast::<u8>().read());
            (*vector).begin = storage as u32;
            (*vector).end = storage.add(len + 1) as u32;
            (*vector).capacity = storage.add(len + 8) as u32;
        }
    }

    #[test]
    fn append_boundaries_preserve_neighbors_and_growth_updates() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::BYTE_VECTOR_OWNER8_PUSH_BACK, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/byte_vector_owner8_push_back"));
            return;
        };
        unsafe {
            slab.write_bytes(0x5a, 0x1000);
            let owner = slab.add(0x100);
            let vector = owner.add(8).cast::<ByteVector>();
            let storage = slab.add(0x400);
            vector.write(ByteVector { begin: storage as u32, end: storage as u32, capacity: storage.add(3) as u32 });
            for value in [0u32, 0xffff_ffff, 0x1234_5680] {
                byte_vector_owner8_push_back(owner, value);
            }
            assert_eq!(core::slice::from_raw_parts(storage, 4), &[0, 255, 128, 0x5a]);
            assert_eq!((*vector).begin, storage as u32);
            assert_eq!((*vector).end, storage.add(3) as u32);
            assert_eq!((*vector).capacity, storage.add(3) as u32);
            assert_eq!(core::slice::from_raw_parts(owner, 8), &[0x5a; 8]);
            assert_eq!(owner.add(20).read(), 0x5a);

            core::ptr::addr_of_mut!(OWNER8_BYTE_INSERT).write(grow);
            byte_vector_owner8_push_back(owner, 0xaabb_cc42);
            let relocated = (*vector).begin as *const u8;
            assert_eq!(core::slice::from_raw_parts(relocated, 4), &[0, 255, 128, 0x42]);
            assert_eq!((*vector).end, relocated.add(4) as u32);
            assert_eq!((*vector).capacity, relocated.add(11) as u32);

            vector.write(ByteVector { begin: 0, end: 0, capacity: 0 });
            byte_vector_owner8_push_back(owner, 0xffff_ff19);
            assert_eq!(((*vector).begin as *const u8).read(), 0x19);
            assert_eq!((*vector).end, (*vector).begin + 1);
            core::ptr::addr_of_mut!(OWNER8_BYTE_INSERT).write(missing_insert);

            vector.write(ByteVector { begin: 0, end: 0, capacity: 1 });
            byte_vector_owner8_push_back(owner, 0xff);
            assert_eq!((*vector).end, 1);
            assert_eq!((*vector).begin, 0);
            assert_eq!((*vector).capacity, 1);
        }
    }
}
