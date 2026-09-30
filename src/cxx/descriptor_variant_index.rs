//! Descriptor-selected variant index — retailOS `FUN_082b512c` at
//! `0x082b512c`, 16 bytes, two plain inbound BL calls and zero predicated BLs.
//!
//! Raw words: `e5900000 e5911004 e7900001 e12fff1e`:
//! `ldr r0,[r0]; ldr r1,[r1,#4]; ldr r0,[r0,r1]; bx lr`.
//! The next real function starts at 0x082b513c. There are no outbound calls.
//! Follow the object slot's target-width pointer, load the byte offset from
//! descriptor word 1, and return the signed word at that offset. Consumers
//! 0x0803b174 and 0x080c8670 compare this index against zero and the
//! descriptor's variant count before selecting a 20-byte variant record.
//! No bounds or NULL checks are performed. Concrete class identity is unknown.
//! Deliberate deviations: none; address addition wraps at the target's 32 bits.

/// Read the variant index at the descriptor-selected offset.
///
/// # Safety
/// `object_slot` must hold a readable 32-bit target address; `descriptor`
/// must contain at least two readable words. The address formed by wrapping
/// addition of the object address and descriptor word 1 must name an aligned,
/// readable `i32`. Neither input nor the resulting address may be invalid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn descriptor_variant_index(
    object_slot: *const u32, descriptor: *const u32,
) -> i32 {
    let object = unsafe { object_slot.read() };
    let offset = unsafe { descriptor.add(1).read() };
    unsafe { (object.wrapping_add(offset) as usize as *const i32).read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn selects_signed_indices_by_byte_offset_and_reloads_the_object_slot() {
        let Some(slab) = try_map_u32_slab(hints::DESCRIPTOR_VARIANT_INDEX, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx::descriptor_variant_index"));
            return;
        };
        let first = unsafe { slab.add(0x100).cast::<i32>() };
        let second = unsafe { slab.add(0x200).cast::<i32>() };
        let values = [0, -1, i32::MIN, i32::MAX, 3];
        unsafe {
            for (index, value) in values.iter().enumerate() {
                first.add(index).write(*value);
                second.add(index).write(!*value);
            }
        }
        let mut slot = first as usize as u32;
        let mut descriptor = [0xffff_ffff, 0, 0xdead_beef];
        for (index, expected) in values.iter().enumerate() {
            descriptor[1] = (index * 4) as u32;
            assert_eq!(unsafe { descriptor_variant_index(&slot, descriptor.as_ptr()) }, *expected);
        }
        slot = second as usize as u32;
        assert_eq!(unsafe { descriptor_variant_index(&slot, descriptor.as_ptr()) }, !3);

        // A negative target offset is still a wrapping 32-bit byte addition.
        slot = unsafe { first.add(2) } as usize as u32;
        descriptor[1] = (-8i32) as u32;
        assert_eq!(unsafe { descriptor_variant_index(&slot, descriptor.as_ptr()) }, 0);
        descriptor[1] = (-4i32) as u32;
        assert_eq!(unsafe { descriptor_variant_index(&slot, descriptor.as_ptr()) }, -1);
    }
}
