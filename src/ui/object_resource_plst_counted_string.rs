//! Counted UTF-16 names from the backend's indexed PLST resource table.

use super::object_state::object_backend_for_kind;
use super::plst_counted_string::plst_element_read_counted_string;
use crate::util::string_pool::PARAM_ERR;

/// `FUN_08052f24` @ `0x08052f24`: 80 bytes, ending before the next
/// function's push at `0x08052f74`. Raw-word decoding verifies two plain
/// outbound BLs (backend resolver and PLST reader), no predicated BLs;
/// two plain inbound BLs at `0x081156b0` and `0x08172504`, none predicated.
/// Clears the count, resolves the backend, rejects negative or out-of-range
/// indices with -50, and reads the selected +0xf64 table entry as a PLST
/// counted string. Accepted indices return zero even for empty/foreign items.
/// Deliberate deviations: none observable for valid inputs; existing Rust
/// callees replace stock calls, and pointer fields retain their u32 width.
///
/// # Safety
/// `counted` must be writable for a count and up to 255 UTF-16 units. Stock
/// writes it before its null check, so NULL is not a supported input.
/// `object` must satisfy `object_backend_for_kind`. Nonnegative indices
/// require a readable backend count at +0xf68; accepted indices require a
/// readable u32 table pointer at +0xf64 and a PLST-reader-compatible entry.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resource_plst_counted_string(
    object: *const u8,
    index: i32,
    counted: *mut u16,
) -> i32 {
    counted.write(0);
    let backend = object_backend_for_kind(object);
    if counted.is_null() || index < 0 {
        return PARAM_ERR;
    }
    if index as u32 >= backend.add(0xf68).cast::<u32>().read() {
        return PARAM_ERR;
    }
    let table = backend.add(0xf64).cast::<u32>().read() as usize as *const u32;
    let element = table.add(index as usize).read() as usize as *mut u8;
    plst_element_read_counted_string(element, counted);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::util::string_pool::{PoolEntry, StringPool};
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn bounds_and_selected_strings_through_self_and_proxy() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::OBJECT_RESOURCE_PLST_COUNTED_STRING, 0x5000) else {
            assert!(note_missing_u32_fixture("ui/object_resource_plst_counted_string"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x5000);
            let backend = slab;
            let proxy = slab.add(0x1000);
            let table = slab.add(0x2000).cast::<u32>();
            backend.write(1);
            proxy.write(2);
            let element = slab.add(0x3004); // Align the native-pointer host pool at +0xcc.
            proxy.add(0xefc).cast::<u32>().write(backend as usize as u32);
            backend.add(0xf64).cast::<u32>().write(table as usize as u32);
            backend.add(0xf68).cast::<u32>().write(3);
            table.write(0);
            table.add(1).write(element as usize as u32);
            table.add(2).write(element as usize as u32);
            element.add(4).cast::<u32>().write(0x706c7374);
            let pool = element.add(0xcc).cast::<StringPool>();
            (*pool).tag = 0x73747263;
            let mut entries = [PoolEntry { blob_offset: 0, length: 6 }];
            let mut entry_ptr = entries.as_mut_ptr();
            let text = [0x0041u16, 0x03a9, 0];
            let mut payload = text.as_ptr() as *mut u8;
            (*pool).entries = &mut entry_ptr;
            (*pool).payload = &mut payload;
            (*pool).entry_count = 1;
            element.add(0x124).cast::<i32>().write(1);
            for object in [backend, proxy] {
                for index in [i32::MIN, -1, 3, i32::MAX] {
                    let mut out = [0xaaaau16; 256];
                    assert_eq!(object_resource_plst_counted_string(object, index, out.as_mut_ptr()), -50);
                    assert_eq!(&out[..2], &[0, 0xaaaa]);
                }
                let mut out = [0xaaaau16; 256];
                assert_eq!(object_resource_plst_counted_string(object, 0, out.as_mut_ptr()), 0);
                assert_eq!(&out[..2], &[0, 0xaaaa]);
                for index in [1, 2] {
                    assert_eq!(object_resource_plst_counted_string(object, index, out.as_mut_ptr()), 0);
                    assert_eq!(&out[..5], &[3, 0x0041, 0x03a9, 0, 0xaaaa]);
                }
            }
            element.add(4).cast::<u32>().write(0x74646174);
            let mut out = [0xaaaau16; 256];
            assert_eq!(object_resource_plst_counted_string(backend, 2, out.as_mut_ptr()), 0);
            assert_eq!(&out[..2], &[0, 0xaaaa]);
            backend.add(0xf68).cast::<u32>().write(0);
            assert_eq!(object_resource_plst_counted_string(backend, 0, out.as_mut_ptr()), -50);
        }
    }
}
