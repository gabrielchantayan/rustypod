//! Screen index cache invalidation.
//!
//! Original: `FUN_081778f0` @ `0x081778f0`, 28 bytes, ending at
//! the next real entry `0x0817790c` (`ldrb r2,[r0,#0x25]`). Raw aligned
//! ARM BL decoding finds two plain inbound calls (0x082325c0, 0x082398e4),
//! zero predicated calls; the body has one plain BL to vector_clear_elem4
//! at 0x083e6808. Clears the vector at +0x840, retaining its allocation
//! and elements, then writes zero to the validity byte at +0x84c.
//! Deliberate deviations: none on target. Host layout expands the native
//! pointer fields and addresses the validity byte by field, not target offset.

use crate::cxx::templates::{vector_clear_elem4, VectorStorage};

#[repr(C)]
struct ScreenIndexCache {
    prefix: [u32; 0x840 / 4],
    indices: VectorStorage,
    valid: u8,
}

/// Clears the index vector and invalidates its cached state.
///
/// # Safety
/// `screen` must point to an aligned, writable screen object containing the
/// vector head and validity byte (through +0x84c on ARM). On hosts, it must
/// use the native-pointer `ScreenIndexCache` layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn screen_indices_clear(screen: *mut u8) {
    let cache = screen.cast::<ScreenIndexCache>();
    unsafe {
        vector_clear_elem4(core::ptr::addr_of_mut!((*cache).indices));
        core::ptr::addr_of_mut!((*cache).valid).write(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_preserves_storage_elements_and_unrelated_bytes() {
        for live in [0usize, 1, 4] {
            for valid in [0u8, 1, 0x80, 0xff] {
                let mut elements = [0x1234_5678u32, 0x8765_4321, 0, u32::MAX];
                let original = elements;
                let begin = elements.as_mut_ptr().cast::<u8>();
                let capacity = unsafe { begin.add(core::mem::size_of_val(&elements)) };
                let mut cache = ScreenIndexCache {
                    prefix: [0xa5a5_5a5a; 0x840 / 4],
                    indices: VectorStorage {
                        begin,
                        end: unsafe { begin.add(live * 4) },
                        end_of_storage: capacity,
                    },
                    valid,
                };
                unsafe { screen_indices_clear(core::ptr::addr_of_mut!(cache).cast()) };
                assert_eq!(cache.indices.begin, begin);
                assert_eq!(cache.indices.end, begin);
                assert_eq!(cache.indices.end_of_storage, capacity);
                assert_eq!(cache.valid, 0);
                assert_eq!(cache.prefix, [0xa5a5_5a5a; 0x840 / 4]);
                assert_eq!(elements, original);
            }
        }
    }

    #[test]
    fn null_empty_vector_is_invalidated_without_dereferencing_elements() {
        let mut cache = ScreenIndexCache {
            prefix: [0; 0x840 / 4],
            indices: VectorStorage {
                begin: core::ptr::null_mut(),
                end: core::ptr::null_mut(),
                end_of_storage: core::ptr::null_mut(),
            },
            valid: 0xff,
        };
        unsafe { screen_indices_clear(core::ptr::addr_of_mut!(cache).cast()) };
        assert!(cache.indices.begin.is_null());
        assert!(cache.indices.end.is_null());
        assert!(cache.indices.end_of_storage.is_null());
        assert_eq!(cache.valid, 0);
    }
}
