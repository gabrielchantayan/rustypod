//! Q16.16 4x4 matrix identity initializer.

use core::ptr::{addr_of_mut, write_volatile};

/// A 4x4 signed Q16.16 matrix, followed by the matrix identity marker used by
/// the retailOS transform helpers.
#[repr(C)]
pub struct FixedMatrix4x4 {
    /// +0x00..+0x3c: row-major Q16.16 matrix elements.
    pub elements: [i32; 16],
    /// +0x40: set only when this matrix is the known identity matrix.
    pub is_identity: u8,
}

const _: [u8; 0x40] = [0; core::mem::offset_of!(FixedMatrix4x4, is_identity)];
const _: [u8; 0x44] = [0; core::mem::size_of::<FixedMatrix4x4>()];

const Q16_ONE: i32 = 0x0001_0000;

/// fixed_matrix_identity_init — original: `FUN_082570ec` @ **0x082570ec**
/// (84 bytes, `0x082570ec..0x08257140`; raw decoding confirms the separately
/// linked next function begins at `0x08257140`).
///
/// Decoding every ARM B/BL immediate in `osos.dec` verifies 14 direct inbound
/// `bl` call sites and one unconditional tail `b` site (`0x08242ec0`); none
/// are predicated. The leaf stores the Q16.16 value 1.0 (`0x00010000`) at
/// diagonal elements 0, 5, 10, and 15, clears every other matrix element, and
/// writes one to the identity marker at +0x40. Its unusual store order is
/// retained from the raw ARM body. No NULL or alignment guard exists; like the
/// original, callers must provide aligned writable 0x44-byte storage.
///
/// Deliberate deviations: none.
#[cfg_attr(target_os = "none", link_section = ".text.fixed_matrix_identity_init")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed_matrix_identity_init(matrix: *mut FixedMatrix4x4) {
    write_volatile(addr_of_mut!((*matrix).elements[15]), Q16_ONE);
    write_volatile(addr_of_mut!((*matrix).elements[10]), Q16_ONE);
    write_volatile(addr_of_mut!((*matrix).elements[5]), Q16_ONE);
    write_volatile(addr_of_mut!((*matrix).elements[12]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[0]), Q16_ONE);
    write_volatile(addr_of_mut!((*matrix).elements[8]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[4]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[13]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[9]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[1]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[14]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[6]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[2]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[11]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[7]), 0);
    write_volatile(addr_of_mut!((*matrix).elements[3]), 0);
    write_volatile(addr_of_mut!((*matrix).is_identity), 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn identity_init_overwrites_every_matrix_field_and_preserves_padding() {
        let mut storage = MaybeUninit::<FixedMatrix4x4>::uninit();
        unsafe {
            core::ptr::write_bytes(
                storage.as_mut_ptr().cast::<u8>(),
                0xa5,
                core::mem::size_of::<FixedMatrix4x4>(),
            );
            fixed_matrix_identity_init(storage.as_mut_ptr());

            let matrix = storage.assume_init();
            assert_eq!(
                matrix.elements,
                [
                    Q16_ONE, 0, 0, 0,
                    0, Q16_ONE, 0, 0,
                    0, 0, Q16_ONE, 0,
                    0, 0, 0, Q16_ONE,
                ],
            );
            assert_eq!(matrix.is_identity, 1);

            let raw = core::slice::from_raw_parts(
                core::ptr::addr_of!(matrix).cast::<u8>(),
                core::mem::size_of::<FixedMatrix4x4>(),
            );
            assert_eq!(&raw[0x41..0x44], &[0xa5, 0xa5, 0xa5]);
        }
    }
}
