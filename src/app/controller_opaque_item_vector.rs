//! `app_controller_opaque_item_vector_nonempty` — original: `FUN_0817f6b0`
//! @ **0x0817f6b0**.
//!
//! **24 bytes**, `0x0817f6b0..0x0817f6c8`: raw ARM begins with `push {r4,lr}`
//! and ends with `pop {r4,pc}`; `0x0817f6c8` is a separately entered
//! function. Decoding every ARM B/BL word in `osos.dec` finds **8 direct `bl`
//! call sites**, all unconditional, at `0x0816d308`, `0x0817e9d8`,
//! `0x0817ea3c`, `0x0818013c`, `0x08188924`, `0x082883d8`, `0x08288434`, and
//! `0x08288b08`. There are no predicated BL forms or direct plain-B tail calls.
//!
//! # Algorithm
//!
//! Passes the embedded `std::vector` head at controller `+0x58` to the
//! already-ported 4-byte-element `vector::size()` instantiation, then returns
//! whether that signed count is nonzero. The raw body deliberately preserves
//! a negative count from a reversed span as true.
//!
//! # Deliberate deviations
//!
//! The vector's element type has not been recovered. Callers add and remove
//! opaque words, so the port names the member by its observed representation
//! rather than inventing a domain meaning. `VectorBounds` uses native pointer
//! fields for safe host fixtures; its target layout is still two adjacent ARM
//! words.

use crate::cxx::templates::{vector_size_elem4_alias_7a38, VectorBounds};

/// Controller prefix with the opaque 4-byte-element vector at `+0x58`.
#[repr(C)]
pub struct AppControllerOpaqueItemVector {
    _prefix: [u8; 0x58],
    pub opaque_items: VectorBounds,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x58] = [0; core::mem::offset_of!(AppControllerOpaqueItemVector, opaque_items)];

/// Returns whether the controller's opaque-item vector has a nonzero
/// 4-byte-element count.
///
/// Original: `FUN_0817f6b0` @ `0x0817f6b0` (24 bytes, **8 unconditional
/// `bl` call sites**, binary-scanned). As in retailOS, `controller` is
/// dereferenced without a NULL guard.
///
/// # Safety
///
/// `controller` must point to a readable [`AppControllerOpaqueItemVector`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_controller_opaque_item_vector_nonempty(
    controller: *const AppControllerOpaqueItemVector,
) -> u32 {
    (vector_size_elem4_alias_7a38(core::ptr::addr_of!((*controller).opaque_items)) != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller_with_bounds(begin: *mut u8, end: *mut u8) -> AppControllerOpaqueItemVector {
        AppControllerOpaqueItemVector {
            _prefix: [0xa5; 0x58],
            opaque_items: VectorBounds { begin, end },
        }
    }

    #[test]
    fn empty_vector_returns_zero() {
        let controller = controller_with_bounds(core::ptr::null_mut(), core::ptr::null_mut());

        assert_eq!(unsafe { app_controller_opaque_item_vector_nonempty(&controller) }, 0);
    }

    #[test]
    fn complete_elements_return_one() {
        let mut elements = [0u32; 4];
        let begin = elements.as_mut_ptr().cast::<u8>();
        let controller = controller_with_bounds(begin, unsafe { begin.add(12) });

        assert_eq!(unsafe { app_controller_opaque_item_vector_nonempty(&controller) }, 1);
    }

    #[test]
    fn reversed_span_remains_nonzero() {
        let mut elements = [0u32; 4];
        let begin = unsafe { elements.as_mut_ptr().cast::<u8>().add(12) };
        let controller = controller_with_bounds(begin, unsafe { begin.sub(4) });

        assert_eq!(unsafe { app_controller_opaque_item_vector_nonempty(&controller) }, 1);
    }

    #[test]
    fn sub_element_span_has_zero_size() {
        let mut elements = [0u32; 1];
        let begin = elements.as_mut_ptr().cast::<u8>();
        let controller = controller_with_bounds(begin, unsafe { begin.add(2) });

        assert_eq!(unsafe { app_controller_opaque_item_vector_nonempty(&controller) }, 0);
    }
}
