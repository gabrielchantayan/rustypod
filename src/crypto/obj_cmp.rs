//! OpenSSL ASN.1 object comparator — `FUN_0805eb74` @ 0x0805eb74.
//!
//! Raw `osos.dec` words establish a 32-byte body (`0x0805eb74..0x0805eb94`);
//! `0x0805eb94` is the next separately entered function. It has four inbound
//! plain `bl` call sites (`0x0806f414`, `0x0806f5e4`, `0x08071414`, and
//! `0x08084a50`), zero predicated `bl` call sites, and no internal `bl`.
//! It subtracts the target-width `ASN1_OBJECT::length` fields at word 3 and,
//! on equality, tail-branches to `memcmp` for that many bytes from word 4.
//!
//! Deliberate deviation: the target's 32-bit pointer fields are accessed as
//! u32 words rather than a host `ASN1_OBJECT` layout, whose pointers are wider.

/// obj_cmp — orders DER object identifiers by encoded length, then bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn obj_cmp(a: *const u32, b: *const u32) -> i32 {
    let len = a.add(3).read();
    let length_difference = len.wrapping_sub(b.add(3).read()) as i32;
    if length_difference != 0 {
        return length_difference;
    }

    crate::libc::memcmp::memcmp(
        a.add(4).read() as usize as *const u8,
        b.add(4).read() as usize as *const u8,
        len as usize,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    unsafe fn write_object(object: *mut u32, data: *const u8, len: u32) {
        object.add(3).write(len);
        object.add(4).write(data as usize as u32);
    }

    #[test]
    fn orders_length_before_der_bytes() {
        let Some(slab) = try_map_u32_slab(hints::OBJ_CMP, 4096) else {
            assert!(note_missing_u32_fixture("crypto/obj_cmp"));
            return;
        };
        unsafe {
            let objects = slab as *mut u32;
            let data = slab.add(256);
            let short = data;
            let long = data.add(16);
            let earlier = data.add(32);
            let later = data.add(48);
            core::ptr::copy_nonoverlapping([0x2a, 0x03].as_ptr(), short, 2);
            core::ptr::copy_nonoverlapping([0x2a, 0x03, 0x04].as_ptr(), long, 3);
            core::ptr::copy_nonoverlapping([0x2a, 0x02].as_ptr(), earlier, 2);
            core::ptr::copy_nonoverlapping([0x2a, 0x04].as_ptr(), later, 2);
            write_object(objects, short, 2);
            write_object(objects.add(6), long, 3);
            write_object(objects.add(12), earlier, 2);
            write_object(objects.add(18), later, 2);

            assert_eq!(obj_cmp(objects, objects.add(6)), -1);
            assert_eq!(obj_cmp(objects.add(6), objects), 1);
            assert_eq!(obj_cmp(objects, objects), 0);
            assert_eq!(obj_cmp(objects.add(12), objects.add(18)), -2);
            assert_eq!(obj_cmp(objects.add(18), objects.add(12)), 2);
        }
    }

    #[test]
    fn equal_zero_lengths_do_not_dereference_data() {
        let Some(slab) = try_map_u32_slab(hints::OBJ_CMP_ZERO, 4096) else {
            assert!(note_missing_u32_fixture("crypto/obj_cmp"));
            return;
        };
        unsafe {
            let objects = slab as *mut u32;
            write_object(objects, core::ptr::null(), 0);
            write_object(objects.add(6), core::ptr::null(), 0);
            assert_eq!(obj_cmp(objects, objects.add(6)), 0);
        }
    }
}
