//! Node bounds getter — original `FUN_080513d0` @ `0x080513d0`.
//! True extent: 48 bytes, `0x080513d0..0x08051400`; the next entry
//! starts with `cmp r0, #0`. Raw word decoding verifies two incoming plain
//! BL sites (0x080fe18c, 0x081142ac), no incoming predicated BLs, and one
//! outgoing BLNE (no plain BL) to the memcpy veneer at 0x08037db0.
//!
//! Reject a null node with -192. For a non-null output, copy the eight-byte
//! rectangle at node +0x10; otherwise succeed without reading node memory.
//! Callers subtract signed 16-bit endpoint coordinates to obtain dimensions.
//! The veneer words e51ff004/22000020 identify the IRAM mirror of the
//! already-ported __rt_memcpy at 0x08000020, not mask ROM.
//! Deliberate deviations: call the Rust copy implementation directly through
//! a volatile function pointer to retain the real call and avoid LLVM builtin
//! substitution. Its different return pointer is ignored, as in the original.

use crate::libc::rt_memcpy::__rt_memcpy;

/// # Safety
/// When both pointers are non-null, `node` must provide readable storage
/// through byte +0x17 (plus copy-helper funnel padding for misalignment),
/// and `output` must be writable for eight bytes without overlapping that
/// source range. Neither pointer is dereferenced on either null path.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_node_bounds_copy(node: *const u8, output: *mut u8) -> i32 {
    if node.is_null() {
        return -192;
    }
    if !output.is_null() {
        let copy: unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 = __rt_memcpy;
        let copy = core::ptr::read_volatile(&copy);
        copy(output, node.add(0x10), 8);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_node_rejects_without_changing_output() {
        let mut output = [0xa5; 12];
        unsafe {
            assert_eq!(ui_node_bounds_copy(core::ptr::null(), output.as_mut_ptr()), -192);
            assert_eq!(ui_node_bounds_copy(core::ptr::null(), core::ptr::null_mut()), -192);
        }
        assert_eq!(output, [0xa5; 12]);
    }

    #[test]
    fn null_output_does_not_read_node() {
        assert_eq!(unsafe {
            ui_node_bounds_copy(core::ptr::dangling::<u8>(), core::ptr::null_mut())
        }, 0);
    }

    #[test]
    fn copies_only_bounds_for_every_pointer_alignment() {
        // Word-aligned backing storage plus padding for the copy funnel.
        for source_alignment in 0..4 {
            for output_alignment in 0..4 {
                let mut node_words = [0xcccc_ccccu32; 9];
                let mut output_words = [0xa5a5_a5a5u32; 4];
                let bounds = [0x00, 0x80, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00];
                unsafe {
                    let node_bytes = core::slice::from_raw_parts_mut(node_words.as_mut_ptr().cast::<u8>(), 36);
                    node_bytes[source_alignment + 16..source_alignment + 24].copy_from_slice(&bounds);
                    let before = node_words;
                    let node = node_words.as_ptr().cast::<u8>().add(source_alignment);
                    let output = output_words.as_mut_ptr().cast::<u8>().add(output_alignment);
                    assert_eq!(ui_node_bounds_copy(node, output), 0);
                    let actual = core::slice::from_raw_parts(output_words.as_ptr().cast::<u8>(), 16);
                    let mut expected = [0xa5; 16];
                    expected[output_alignment..output_alignment + 8].copy_from_slice(&bounds);
                    assert_eq!(actual, expected);
                    assert_eq!(node_words, before);
                }
            }
        }
    }
}
