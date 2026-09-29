//! `pthread_mutexattr_init` — original: `FUN_082e84a4` @ 0x082e84a4.
//!
//! Raw `osos.dec` words establish the true extent as 52 bytes
//! (0x082e84a4..0x082e84d8): the next word is the `MTXA` literal, not code.
//! It has no outbound plain or predicated `bl`; CodeGraph confirms two inbound
//! plain `bl` call sites. On NULL, return 0x1a without stores. Otherwise write
//! the `MTXA` magic at +0, 0xffc2 at +4, clear bits 0..5 of the halfword at
//! +6, set bit 3, and return zero. No deliberate deviations.
//!
//! `cxx_mutexattr_init` — original: `FUN_08261d1c` @ 0x08261d1c (20 bytes,
//! all code). It is a five-instruction C++ veneer: call this initializer,
//! discard its status, and return the original attribute pointer.

/// Status `pthread_mutexattr_init` @ 0x082e84a4 returns on success.
pub const MUTEXATTR_INIT_OK: u32 = 0;

/// Status it returns for a NULL attribute.
pub const MUTEXATTR_INIT_INVALID: u32 = 0x1a;

/// The attribute magic planted at attr+0x00 ("MTXA"; literal @ 0x082e84d8).
pub const MUTEXATTR_MAGIC: u32 = 0x4d54_5841;

/// The default halfword planted at attr+0x04.
pub const MUTEXATTR_DEFAULT_HALFWORD: u16 = 0xffc2;

/// The low six bits cleared in the attr+0x06 halfword.
pub const MUTEXATTR_SCOPE_CLEAR_MASK: u16 = 0x003f;

/// The process-scope bit set in the attr+0x06 halfword.
pub const MUTEXATTR_PROCESS_SCOPE_BIT: u16 = 0x0008;

/// `pthread_mutexattr_init` — original: `FUN_082e84a4` @ 0x082e84a4
/// (52 bytes; 0 outbound `bl`, 2 inbound plain `bl` call sites).
///
/// Initializes the eight-byte pthread attribute object directly with its
/// target byte offsets; `attr` is a byte pointer so host pointer width cannot
/// alter the +4 and +6 field locations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pthread_mutexattr_init(attr: *mut u8) -> u32 {
    if attr.is_null() {
        return MUTEXATTR_INIT_INVALID;
    }
    attr.cast::<u32>().write(MUTEXATTR_MAGIC);
    attr.add(4).cast::<u16>().write(MUTEXATTR_DEFAULT_HALFWORD);
    let scope = attr.add(6).cast::<u16>();
    scope.write((scope.read() & !MUTEXATTR_SCOPE_CLEAR_MASK) | MUTEXATTR_PROCESS_SCOPE_BIT);
    MUTEXATTR_INIT_OK
}

/// cxx_mutexattr_init — original: `FUN_08261d1c` @ 0x08261d1c
/// (20 bytes; 2 inbound `bl` call sites).
///
/// Forwards `attr` to `pthread_mutexattr_init`, discards its status, and
/// returns `attr` itself (`mov r0, r4`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutexattr_init(attr: *mut usize) -> *mut usize {
    pthread_mutexattr_init(attr.cast());
    attr
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(align(8))]
    struct AttrBytes([u8; 16]);

    fn reference_init(attr: &mut [u8; 8]) {
        attr[0..4].copy_from_slice(&MUTEXATTR_MAGIC.to_le_bytes());
        attr[4..6].copy_from_slice(&MUTEXATTR_DEFAULT_HALFWORD.to_le_bytes());
        let halfword = u16::from_le_bytes([attr[6], attr[7]]);
        attr[6..8].copy_from_slice(
            &((halfword & !MUTEXATTR_SCOPE_CLEAR_MASK) | MUTEXATTR_PROCESS_SCOPE_BIT)
                .to_le_bytes(),
        );
    }

    #[test]
    fn initializes_all_scope_flag_inputs_without_touching_the_guard() {
        for seed6 in [0x0000u16, 0xffff, 0x003f, 0xffc0, 0xaa95] {
            let mut buf = AttrBytes([0xa5; 16]);
            buf.0[6..8].copy_from_slice(&seed6.to_le_bytes());
            let mut expected = buf.0;
            reference_init((&mut expected[..8]).try_into().unwrap());

            assert_eq!(
                unsafe { pthread_mutexattr_init(buf.0.as_mut_ptr()) },
                MUTEXATTR_INIT_OK,
                "seed +6 = {seed6:#06x}"
            );
            assert_eq!(buf.0, expected, "seed +6 = {seed6:#06x}");
        }
    }

    #[test]
    fn null_returns_invalid_without_stores() {
        assert_eq!(
            unsafe { pthread_mutexattr_init(core::ptr::null_mut()) },
            MUTEXATTR_INIT_INVALID
        );
    }

    #[test]
    fn cxx_veneer_discards_status_and_returns_the_original_pointer() {
        let mut scope = [0xa5a5_a5a5usize; 2];
        let attr = scope.as_mut_ptr();

        assert_eq!(unsafe { cxx_mutexattr_init(attr) }, attr);
        assert_eq!(scope[0] as u32, MUTEXATTR_MAGIC);
    }
}
