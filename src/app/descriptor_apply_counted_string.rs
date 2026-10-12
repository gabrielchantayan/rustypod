//! Lookup a linked descriptor, set its value, and apply a counted string.

use core::ptr;
use crate::ui::object_packed_field_ensure_one::ensure_object_packed_field_is_one;
use crate::ui::plst_apply_counted_string::plst_apply_counted_string;
use super::descriptor_lookup_attach::lookup_and_attach_descriptor;

/// Original FUN_0803bea0 at 0x0803bea0: 104 bytes, ending at the independent
/// PUSH at 0x0803bf08. Two inbound plain BLs (0x081a3d5c, 0x081a4414),
/// three outbound plain BLs (0x0803becc, 0x0803bed8, 0x0803bef4), no
/// predicated BLs in either direction and no literal pool.
///
/// Reject a NULL key or missing owner at context+0xf50 with -50. Lookup and
/// attach with NULL attachment context and option zero, then ensure the
/// context-selected packed field is one, ignoring that result. Write value
/// to the linked descriptor at +0x5c and apply the counted string. Return
/// zero only for apply status zero; otherwise return -20.
/// Deliberate deviations: calls reuse the three existing Rust ports. The
/// NULL-link check remains AFTER the packed-field call: retail dereferences
/// NULL there on lookup failure, so that path is not made safe here.
///
/// # Safety
/// For a non-NULL key, context must be aligned and readable through +0xf53.
/// All lookup, attachment, packed-field, and string-application contracts
/// must hold. In particular lookup must return a valid link, with a writable
/// descriptor through +0x5f. Context byte +1 selects the packed field.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn descriptor_apply_counted_string(
    context: *mut u32,
    key: *const u8,
    counted: *const u16,
    value: u32,
) -> i32 {
    apply_with(context, key, counted, value, lookup_and_attach_descriptor, plst_apply_counted_string)
}

#[inline(always)]
unsafe fn apply_with(
    context: *mut u32,
    key: *const u8,
    counted: *const u16,
    value: u32,
    lookup: unsafe extern "C" fn(*mut u32, *const u8, *mut u8, u32) -> *mut u32,
    apply: unsafe extern "C" fn(*mut u8, *const u16) -> i32,
) -> i32 {
    if key.is_null() { return -50; }
    let owner = context.add(0xf50 / 4).read() as usize as *mut u32;
    if owner.is_null() { return -50; }
    let link = lookup(owner, key, ptr::null_mut(), 0);
    ensure_object_packed_field_is_one(link.cast(), context.cast());
    if !link.is_null() {
        let descriptor = link.add(0x20 / 4).read() as usize as *mut u32;
        descriptor.add(0x5c / 4).write(value);
        if apply(link.cast(), counted) == 0 { return 0; }
    }
    -20
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    unsafe extern "C" fn link_from_key(_: *mut u32, key: *const u8, _: *mut u8, _: u32) -> *mut u32 {
        key as *mut u32
    }
    unsafe extern "C" fn status_from_counted(_: *mut u8, counted: *const u16) -> i32 {
        counted.cast::<i32>().read()
    }

    #[test]
    fn null_key_does_not_read_context_and_missing_owner_rejects() {
        unsafe {
            assert_eq!(descriptor_apply_counted_string(ptr::null_mut(), ptr::null(), ptr::null(), 9), -50);
            let mut context = [0u32; 0xf54 / 4];
            let key = [0u8];
            assert_eq!(descriptor_apply_counted_string(context.as_mut_ptr(), key.as_ptr(), ptr::null(), 9), -50);
        }
    }

    #[test]
    fn status_mapping_preserves_value_write_and_packed_field_transitions() {
        let Some(slab) = try_map_u32_slab(hints::DESCRIPTOR_APPLY_COUNTED_STRING, 0x3000) else {
            crate::testing::note_missing_u32_fixture("app::descriptor_apply_counted_string"); return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x3000);
            let context = slab.cast::<u32>();
            let link = slab.add(0x1000).cast::<u32>();
            let descriptor = slab.add(0x2000).cast::<u32>();
            context.add(0xf50 / 4).write(slab as u32);
            link.add(8).write(descriptor as u32);
            for selector in [0u8, 1, 3, 4, 128, 255] {
                *slab.add(1) = selector;
                for initial in [0u8, 0x55, 0xaa, 0xff] {
                    for status in [0i32, 1, -7, i32::MIN] {
                        *link.cast::<u8>().add(0x1c) = initial;
                        descriptor.add(22).write(0x1234);
                        descriptor.add(24).write(0x5678);
                        let value = status as u32 ^ 0xa5a5_5a5a;
                        let result = apply_with(context, link.cast(), (&status as *const i32).cast(), value, link_from_key, status_from_counted);
                        assert_eq!(result, if status == 0 { 0 } else { -20 });
                        assert_eq!(descriptor.add(23).read(), value);
                        assert_eq!(descriptor.add(22).read(), 0x1234);
                        assert_eq!(descriptor.add(24).read(), 0x5678);
                        let shift = ((selector & 3) * 2) as u32;
                        let expected = if selector & 0x7c == 0 && (initial >> shift) & 3 == 0 {
                            initial | (1 << shift)
                        } else { initial };
                        assert_eq!(*link.cast::<u8>().add(0x1c), expected);
                    }
                }
            }
        }
    }
}
