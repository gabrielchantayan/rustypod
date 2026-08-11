//! FreeType validator initialization.

/// The 16-byte initialized prefix of FreeType's `FT_ValidatorRec`.
///
/// The full retailOS record continues with its jump buffer.  This routine
/// touches only these first four fields.  The `base` and `limit` addresses are
/// explicitly target-width words: retailOS is a 32-bit ARM image, so keeping
/// them as `u32` preserves the raw record layout on 64-bit host tests.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FtValidatorPrefix {
    pub base: u32,
    pub limit: u32,
    pub level: u8,
    _padding: [u8; 3],
    pub error: i32,
}

/// `ft_validator_init` — original: `FUN_082cfe68` @ 0x082cfe68 (20 bytes).
///
/// Initializes the first 16 bytes of an `FT_ValidatorRec`: records the
/// target-width table bounds, selects the validation level, and clears the
/// `FT_Error` result.  The raw ARM body is `stmia r0,{r1,r2}; strb r3,[r0,#8];
/// str #0,[r0,#12]; bx lr`.  It is FreeType's `ft_validator_init` from
/// `ftobjs.c`; its 0x082cfe58 sibling allocates a containing record and then
/// runs this exact initialization on the validator prefix.
///
/// # Safety
/// `validator` must be valid and aligned for one writable
/// [`FtValidatorPrefix`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_validator_init(
    validator: *mut FtValidatorPrefix,
    base: u32,
    limit: u32,
    level: u8,
) {
    core::ptr::addr_of_mut!((*validator).base).write(base);
    core::ptr::addr_of_mut!((*validator).limit).write(limit);
    core::ptr::addr_of_mut!((*validator).level).write(level);
    core::ptr::addr_of_mut!((*validator).error).write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{ft_validator_init, FtValidatorPrefix};

    #[repr(C)]
    struct GuardedPrefix {
        before: [u8; 4],
        validator: FtValidatorPrefix,
        after: [u8; 4],
    }

    #[test]
    fn initializes_all_fields_without_touching_padding_or_adjacency() {
        const GUARD: u8 = 0xa5;
        let mut guarded = GuardedPrefix {
            before: [GUARD; 4],
            validator: FtValidatorPrefix {
                base: 0x1111_1111,
                limit: 0x2222_2222,
                level: 0x33,
                _padding: [0x5c; 3],
                error: -1,
            },
            after: [GUARD; 4],
        };

        unsafe {
            ft_validator_init(&mut guarded.validator, 0x0804_f000, 0x0805_0000, 2);
        }

        assert_eq!(guarded.before, [GUARD; 4], "bytes preceding the prefix");
        assert_eq!(guarded.after, [GUARD; 4], "bytes following the prefix");
        assert_eq!(guarded.validator.base, 0x0804_f000);
        assert_eq!(guarded.validator.limit, 0x0805_0000);
        assert_eq!(guarded.validator.level, 2);
        assert_eq!(guarded.validator.error, 0);
        assert_eq!(guarded.validator._padding, [0x5c; 3], "strb leaves +9..+11");

        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&guarded.validator as *const FtValidatorPrefix).cast::<u8>(),
                core::mem::size_of::<FtValidatorPrefix>(),
            )
        };
        assert_eq!(
            bytes,
            [
                0x00, 0xf0, 0x04, 0x08, 0x00, 0x00, 0x05, 0x08, 0x02, 0x5c, 0x5c, 0x5c,
                0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn preserves_each_target_width_bound_and_stores_the_full_level_byte() {
        let mut validator = FtValidatorPrefix {
            base: 0,
            limit: 0,
            level: 0,
            _padding: [0; 3],
            error: -1,
        };

        unsafe {
            ft_validator_init(&mut validator, u32::MAX, 0x8000_0001, u8::MAX);
        }

        assert_eq!(validator.base, u32::MAX);
        assert_eq!(validator.limit, 0x8000_0001);
        assert_eq!(validator.level, u8::MAX);
        assert_eq!(validator.error, 0);
    }
}
