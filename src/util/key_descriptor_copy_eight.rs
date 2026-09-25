//! `key_descriptor_copy_eight` — original: `FUN_08054cd8` @ `0x08054cd8`
//! (80 bytes; `0x08054cd8..0x08054d28`).
//!
//! Full-image A32 branch decoding finds three inbound plain unconditional `bl`
//! calls and no predicated `bl` calls. The body has one plain `bl`, to the ROM
//! `__rt_memcpy` veneer at `0x08037db0`.
//!
//! # Algorithm
//!
//! Validate a descriptor and output pointer. A valid descriptor has a zero
//! low byte at `+0x08`, a nonzero target pointer at `+0x0c`, and kind `0x44`
//! at `+0x10`; copy the two words at that target pointer to `out`. Invalid
//! arguments or descriptor state return `-50` without writing `out`.
//!
//! # Deliberate deviations
//!
//! The ROM memcpy veneer is represented by the established Rust
//! [`crate::libc::rt_memcpy::__rt_memcpy`] seam.

use crate::libc::rt_memcpy::__rt_memcpy;

const INVALID_DESCRIPTOR: i32 = -50;
const DESCRIPTOR_KIND: u32 = 0x44;
const COPY_BYTES: usize = 8;

/// Copies the two-word value referenced by a validated key descriptor.
///
/// `descriptor` is target-width storage readable through `+0x10`; its word
/// at `+0x0c` is a 32-bit target address. `out` is writable for eight bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.key_descriptor_copy_eight")]
#[inline(never)]
pub unsafe extern "C" fn key_descriptor_copy_eight(descriptor: *const u32, out: *mut u32) -> i32 {
    if descriptor.is_null() || out.is_null()
        || descriptor.cast::<u8>().add(8).read() != 0
        || descriptor.add(3).read() == 0
        || descriptor.add(4).read() != DESCRIPTOR_KIND {
        return INVALID_DESCRIPTOR;
    }

    let source = descriptor.add(3).read() as usize as *const u8;
    __rt_memcpy(out.cast(), source, COPY_BYTES);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn copies_only_for_a_valid_descriptor() {
        let Some(slab) = try_map_u32_slab(hints::KEY_DESCRIPTOR_EIGHT_BYTE_COPY, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let descriptor = unsafe { slab.add(0x100).cast::<u32>() };
        let source = unsafe { slab.add(0x200).cast::<u32>() };
        let out = unsafe { slab.add(0x300).cast::<u32>() };

        unsafe {
            source.write(0x1122_3344);
            source.add(1).write(0x5566_7788);
            descriptor.add(2).write(0);
            descriptor.add(3).write(source as usize as u32);
            descriptor.add(4).write(DESCRIPTOR_KIND);
            out.write(0xcccc_cccc);
            out.add(1).write(0xdddd_dddd);

            assert_eq!(key_descriptor_copy_eight(descriptor, out), 0);
            assert_eq!([out.read(), out.add(1).read()], [0x1122_3344, 0x5566_7788]);

            for (byte_flag, source_address, kind) in [(1, source as usize as u32, DESCRIPTOR_KIND), (0, 0, DESCRIPTOR_KIND), (0, source as usize as u32, 0)] {
                descriptor.add(2).write(byte_flag);
                descriptor.add(3).write(source_address);
                descriptor.add(4).write(kind);
                out.write(0xcccc_cccc);
                out.add(1).write(0xdddd_dddd);
                assert_eq!(key_descriptor_copy_eight(descriptor, out), INVALID_DESCRIPTOR);
                assert_eq!([out.read(), out.add(1).read()], [0xcccc_cccc, 0xdddd_dddd]);
            }

            assert_eq!(key_descriptor_copy_eight(core::ptr::null(), out), INVALID_DESCRIPTOR);
            assert_eq!(key_descriptor_copy_eight(descriptor, core::ptr::null_mut()), INVALID_DESCRIPTOR);
        }
    }
}
