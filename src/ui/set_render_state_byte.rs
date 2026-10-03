//! Update a UI element's render-state byte and clear its context's words.
//!
//! `ui_element_set_render_state_byte` — `FUN_0826cb78` at **0x0826cb78**.
//! Raw extent: 40 bytes; the independently referenced empty function at
//! 0x0826cba0 is the next boundary. Two incoming plain BL calls at
//! 0x08185568 and 0x08185574, zero predicated BL calls. The body has one
//! plain BL to 0x082a2670 and a tail B to 0x0828d57c.
//!
//! Compare the byte at +0x94 with the full argument. On a difference,
//! store the low byte, then, only if the direct context at +0x3c exists,
//! resolve that context and clear/dispatch its word vector. The byte's
//! higher-level interpretation is not established by the callers.
//!
//! Deliberate deviations: the tail branch is a Rust call to the existing
//! port. Host context pointers widen at the resolver's existing byte offset;
//! device context words remain aligned 32-bit reads. No value normalization.

use crate::ui::coordinate_owner_clear_words::{coordinate_owner_clear_words, CoordinateWordOwner};
use crate::ui::render_context::ui_element_resolve_render_context;

/// # Safety
/// `element` must contain writable retail element fields through +0x94.
/// A non-null direct render context must satisfy `coordinate_owner_clear_words`.
/// Hosts use the existing resolver's native pointer field at +0x3c.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_set_render_state_byte(element: *mut u8, state: u32) {
    unsafe {
        let stored = element.add(0x94);
        if stored.read() as u32 == state {
            return;
        }
        stored.write(state as u8);
        #[cfg(target_os = "none")]
        let has_context = element.add(0x3c).cast::<u32>().read() != 0;
        #[cfg(not(target_os = "none"))]
        let has_context = !element.add(0x3c).cast::<*mut u8>().read_unaligned().is_null();
        if has_context {
            let context = ui_element_resolve_render_context(element);
            coordinate_owner_clear_words(context.cast::<CoordinateWordOwner>());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::coordinate_owner_clear_words::OwnerWordVector;
    use core::ptr;

    #[test]
    fn transitions_compare_full_argument_and_preserve_storage() {
        for (old, requested, cleared) in [(0, 0, false), (7, 7, false),
            (0, 1, true), (1, 0, true), (255, 255, false),
            (255, 511, true), (0, 256, true), (9, u32::MAX, true)] {
            let mut data = [11u32, 22, 33];
            let begin = data.as_mut_ptr();
            let end = unsafe { begin.add(3) };
            let mut owner = CoordinateWordOwner {
                prefix: [0; 5],
                words: OwnerWordVector { begin, end, capacity_end: end },
                intervening_words: [0; 22],
                context: ptr::null_mut(),
            };
            let mut element = [0xa5u8; 0x98];
            element[0x94] = old;
            unsafe {
                element.as_mut_ptr().add(0x3c).cast::<*mut u8>()
                    .write_unaligned(ptr::addr_of_mut!(owner).cast());
            }
            let before = element;
            unsafe { ui_element_set_render_state_byte(element.as_mut_ptr(), requested) };
            assert_eq!(element[0x94], requested as u8);
            assert_eq!(&element[..0x94], &before[..0x94]);
            assert_eq!(&element[0x95..], &before[0x95..]);
            assert_eq!(owner.words.end, if cleared { begin } else { end });
            assert_eq!(owner.words.capacity_end, end);
            assert_eq!(data, [11, 22, 33]);
        }
    }

    #[test]
    fn changed_byte_without_direct_context_does_not_resolve_parent() {
        let mut element = [0u8; 0x98];
        unsafe {
            // Invalid parent would fault if the early return walked ancestors.
            element.as_mut_ptr().add(0x34).cast::<*mut u8>()
                .write_unaligned(ptr::dangling_mut::<u8>());
            element.as_mut_ptr().add(0x3c).cast::<*mut u8>()
                .write_unaligned(ptr::null_mut());
            ui_element_set_render_state_byte(element.as_mut_ptr(), 0x1234);
        }
        assert_eq!(element[0x94], 0x34);
    }
}
