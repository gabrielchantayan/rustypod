//! Counted-string lookup through the object's +0xed4 resource vector.
#[cfg(not(target_os = "none"))]
use crate::cxx::templates::VectorBounds;
use crate::cxx::templates::vector_size_elem16;
use crate::util::string_pool::{string_pool_read_counted, StringPool, PARAM_ERR};
use super::object_state::object_backend_for_kind;

const RESOURCE_VECTOR_OFFSET: usize = 0xed4;
const RESOURCE_ENTRY_SIZE: usize = 16;
const BACKEND_POOL_POINTER_OFFSET: usize = 0xf60;
const STRING_POOL_OFFSET: usize = 0x850;

/// object_resource_vector16_pool850_counted_string — `FUN_080532f4` @
/// 0x080532f4; true extent 112 bytes, ending at the next push at 0x08053364.
/// Raw words verify two plain BLs, zero predicated BLs, and two inbound plain
/// BL callers (0x080669b0, 0x0813bdc0), with no predicated callers.
///
/// Clears the output count, resolves the kind-1 backend or kind-2 proxy, and
/// rejects negative indices or indices outside the object's +0xed4 vector.
/// Bounds comparison is unsigned, using the arithmetic-shift vector count.
/// Loads the selected 16-byte record's first word as the string ID and tail
/// calls the counted reader through backend+0xf60's inline pool at +0x850.
/// Returns the reader status, or -50 for an invalid index.
///
/// Deliberate deviations: pass zero for the reader's dead initial byte length
/// instead of the preserved object pointer in r3. Host builds widen the two
/// target-width vector words before calling the existing vector-size seam.
/// The redundant null check follows an unconditional store in retailOS;
/// null output is not a valid input and Rust omits that check.
///
/// # Safety
/// `counted` must hold a writable count plus 510 payload bytes. `object` must
/// satisfy the backend resolver; accepted indices require readable vector
/// records, backend+0xf60, and a valid inline pool at +0x850.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resource_vector16_pool850_counted_string(
    object: *const u8,
    index: i32,
    counted: *mut u16,
) -> i32 {
    counted.write(0);
    let backend = object_backend_for_kind(object);
    if index < 0 {
        return PARAM_ERR;
    }
    #[cfg(target_os = "none")]
    let vector = object.add(RESOURCE_VECTOR_OFFSET).cast::<crate::cxx::templates::VectorBounds>();
    #[cfg(not(target_os = "none"))]
    let vector_storage = {
        let words = object.add(RESOURCE_VECTOR_OFFSET).cast::<u32>();
        VectorBounds {
            begin: words.read() as usize as *mut u8,
            end: words.add(1).read() as usize as *mut u8,
        }
    };
    #[cfg(not(target_os = "none"))]
    let vector = &vector_storage;
    if index as u32 >= vector_size_elem16(vector) as u32 {
        return PARAM_ERR;
    }
    let table = object.add(RESOURCE_VECTOR_OFFSET).cast::<u32>().read() as usize as *const u8;
    let entry_id = table.add(index as usize * RESOURCE_ENTRY_SIZE).cast::<i32>().read();
    let pool_base = backend.add(BACKEND_POOL_POINTER_OFFSET).cast::<u32>().read() as usize as *mut u8;
    string_pool_read_counted(pool_base.add(STRING_POOL_OFFSET).cast::<StringPool>(), entry_id, counted, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_indices_and_selects_records_from_object_but_pool_from_proxy_backend() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::OBJECT_RESOURCE_VECTOR16_POOL850_COUNTED_STRING, 0x5000,
        ).expect("target-width resource fixture");
        unsafe {
            let object = slab;
            let backend = slab.add(0x1000);
            let table = slab.add(0x2000);
            let pool_base = slab.add(0x3000);
            object.write(2);
            object.add(0xefc).cast::<*const u8>().write(backend);
            object.add(RESOURCE_VECTOR_OFFSET).cast::<u32>().write(table as usize as u32);
            object.add(RESOURCE_VECTOR_OFFSET + 4).cast::<u32>().write(table.add(32) as usize as u32);
            table.cast::<i32>().write(-1);
            table.add(16).cast::<i32>().write(0);
            backend.add(BACKEND_POOL_POINTER_OFFSET).cast::<u32>().write(pool_base as usize as u32);
            let pool = pool_base.add(STRING_POOL_OFFSET).cast::<StringPool>();
            core::ptr::write_bytes(pool, 0, 1);
            (*pool).tag = 0x7374_7263;
            for (index, expected) in [(-1, PARAM_ERR), (i32::MIN, PARAM_ERR),
                (2, PARAM_ERR), (i32::MAX, PARAM_ERR), (0, PARAM_ERR), (1, 0)] {
                let mut output = [0xa5a5u16; 256];
                assert_eq!(object_resource_vector16_pool850_counted_string(object, index, output.as_mut_ptr()), expected);
                assert_eq!(output[0], 0);
                assert!(output[1..].iter().all(|&word| word == 0xa5a5));
            }
            // Empty vectors reject even index zero without accessing the pool.
            object.add(RESOURCE_VECTOR_OFFSET + 4).cast::<u32>().write(table as usize as u32);
            backend.add(BACKEND_POOL_POINTER_OFFSET).cast::<u32>().write(0);
            let mut output = [0xa5a5u16; 256];
            assert_eq!(object_resource_vector16_pool850_counted_string(object, 0, output.as_mut_ptr()), PARAM_ERR);
            assert_eq!(output[0], 0);
            // Kind-1 objects resolve to themselves.
            object.write(1);
            object.add(RESOURCE_VECTOR_OFFSET + 4).cast::<u32>().write(table.add(32) as usize as u32);
            object.add(BACKEND_POOL_POINTER_OFFSET).cast::<u32>().write(pool_base as usize as u32);
            assert_eq!(object_resource_vector16_pool850_counted_string(object, 1, output.as_mut_ptr()), 0);
            assert_eq!(output[0], 0);
            (*pool).tag = 0;
            assert_eq!(object_resource_vector16_pool850_counted_string(object, 1, output.as_mut_ptr()), PARAM_ERR);
        }
    }
}
