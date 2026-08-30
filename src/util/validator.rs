//! FreeType validator record: initialization and the error-raise path.

use crate::runtime::setjmp::JmpBuf;
#[cfg(not(test))]
use crate::runtime::setjmp::longjmp;

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

/// The complete FreeType `FT_ValidatorRec` as the 0x082cfe58 / 0x082cfe68
/// pair sees it: the 16-byte prefix initialized by [`ft_validator_init`],
/// immediately followed at +16 by the 44-byte jump buffer that
/// [`ft_validator_error`] longjmps through. 60 bytes total.
#[repr(C)]
pub struct FtValidator {
    pub prefix: FtValidatorPrefix,
    pub jump_buffer: JmpBuf,
}

/// `ft_validator_error` — original: `FUN_082cfe58` @ 0x082cfe58 (16 bytes).
///
/// FreeType's `ft_validator_error` from `ftobjs.c`: records the validation
/// failure in the record's `error` field, then abandons the parse by
/// `longjmp(&validator->jump_buffer, 1)` back to the `setjmp` in whichever
/// entry point installed the validator. The raw ARM body is exactly
///
/// ```text
/// str r1, [r0, #12]   ; valid->error = error
/// mov r1, #1
/// add r0, r0, #16     ; &valid->jump_buffer
/// bl  longjmp         ; noreturn (0x08031748, already ported)
/// ```
///
/// Verified against osos.dec: 41 call sites — 8 plain `bl` plus 33
/// predicated forms (`blcc`/`blhi`/`blne`/...), i.e. callers raise only
/// when their own bounds or tag check fails, and no data-word references,
/// so it is never dispatched indirectly. Ghidra's 16-byte extent is
/// correct here: the 20 bytes after the `bl` are the adjacent out-of-line
/// [`ft_validator_init`] body @ 0x082cfe68 (ported separately above), NOT
/// dead tail — Ghidra's decompile misreads them as this function's
/// continuation, which is where its phantom `param_3`/`param_4` come from.
/// The real signature takes two arguments and never returns.
///
/// # Safety
/// `validator` must be valid and aligned for one writable [`FtValidator`]
/// whose `jump_buffer` was armed by a live `setjmp`; the call does not
/// return.
/// Test-only observation point replacing the longjmp dispatch, mirroring
/// `runtime::exit`'s `TERMINATE_HOOK`: the ARM `longjmp` body is global_asm
/// and its host shim panics across an `extern "C"` boundary (which aborts
/// rather than unwinds), so host tests install this mock instead. The mock
/// must not return.
#[cfg(test)]
static mut LONGJMP_MOCK: Option<unsafe fn(*const JmpBuf, i32) -> !> = None;

/// Body of [`ft_validator_error`], factored out of the diverging extern
/// wrapper so host tests can `catch_unwind` the mock's panic without
/// crossing an `extern "C"` frame (the same reason `runtime::exit` tests
/// drive `terminate` rather than `exit`).
#[inline]
unsafe fn validator_error_body(validator: *mut FtValidator, error: i32) -> ! {
    core::ptr::addr_of_mut!((*validator).prefix.error).write(error);
    let env = core::ptr::addr_of!((*validator).jump_buffer);
    #[cfg(test)]
    {
        if let Some(mock) = *core::ptr::addr_of!(LONGJMP_MOCK) {
            mock(env, 1);
        }
        panic!("ft_validator_error: LONGJMP_MOCK not installed");
    }
    #[cfg(not(test))]
    longjmp(env, 1)
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_validator_error(validator: *mut FtValidator, error: i32) -> ! {
    validator_error_body(validator, error)
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

    use super::{ft_validator_init, FtValidator, FtValidatorPrefix};
    use crate::runtime::setjmp::JmpBuf;
    use std::boxed::Box;

    /// Serializes mock state and silences the mock's panic output (the
    /// mock stands in for the ARM global_asm longjmp body and panics after
    /// recording, which catch_unwind observes).
    static LONGJMP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static mut MOCK_ENV: *const JmpBuf = core::ptr::null();
    static mut MOCK_VAL: i32 = 0;

    unsafe fn recording_longjmp(env: *const JmpBuf, val: i32) -> ! {
        *core::ptr::addr_of_mut!(MOCK_ENV) = env;
        *core::ptr::addr_of_mut!(MOCK_VAL) = val;
        panic!("recording_longjmp observed the raise");
    }

    /// Installs the recording mock; returns the guard serializing it.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let guard = LONGJMP_LOCK.lock().unwrap();
        unsafe {
            *core::ptr::addr_of_mut!(MOCK_ENV) = core::ptr::null();
            *core::ptr::addr_of_mut!(MOCK_VAL) = 0;
            *core::ptr::addr_of_mut!(super::LONGJMP_MOCK) = Some(recording_longjmp);
        }
        std::panic::set_hook(Box::new(|_| {}));
        guard
    }

    fn armed_validator() -> FtValidator {
        FtValidator {
            prefix: FtValidatorPrefix {
                base: 0x0804_f000,
                limit: 0x0805_0000,
                level: 2,
                _padding: [0x5c; 3],
                error: 0,
            },
            jump_buffer: JmpBuf::new(),
        }
    }

    /// Drives the body; the mock panics, which the catch_unwind converts
    /// into an observable "control left the function" signal. Returns
    /// whether control left.
    fn raise(validator: &mut FtValidator, error: i32) -> bool {
        let validator = validator as *mut FtValidator;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || unsafe {
            super::validator_error_body(validator, error)
        }))
        .is_err()
    }

    #[test]
    fn validator_record_layout_matches_the_raw_offsets() {
        assert_eq!(core::mem::size_of::<FtValidator>(), 60);
        assert_eq!(core::mem::align_of::<FtValidator>(), 4);
        assert_eq!(core::mem::size_of::<FtValidatorPrefix>(), 16);
        assert_eq!(
            core::mem::offset_of!(FtValidator, jump_buffer),
            16,
            "longjmp target is env at +0x10"
        );
        assert_eq!(
            core::mem::offset_of!(FtValidator, prefix.error),
            12,
            "error store is str r1,[r0,#12]"
        );
    }

    #[test]
    fn stores_error_then_transfers_control_without_returning() {
        let _guard = setup();

        let mut validator = armed_validator();
        let expected_env = unsafe {
            core::ptr::addr_of!(validator.jump_buffer)
        };
        let left = raise(&mut validator, 8);

        assert!(left, "longjmp must not return to the caller");
        assert_eq!(
            validator.prefix.error, 8,
            "error store happens before the longjmp"
        );
        // The raise targets the embedded jump buffer at +0x10, with val 1.
        unsafe {
            assert_eq!(*core::ptr::addr_of!(MOCK_ENV), expected_env);
            assert_eq!(*core::ptr::addr_of!(MOCK_VAL), 1);
        }
        // The raise must not disturb the rest of the record.
        assert_eq!(validator.prefix.base, 0x0804_f000);
        assert_eq!(validator.prefix.limit, 0x0805_0000);
        assert_eq!(validator.prefix.level, 2);
        assert_eq!(validator.prefix._padding, [0x5c; 3]);
        // JmpBuf derives no PartialEq; compare the raw 44 bytes instead.
        let env_bytes = unsafe {
            core::slice::from_raw_parts(
                (&validator.jump_buffer as *const JmpBuf).cast::<u8>(),
                core::mem::size_of::<JmpBuf>(),
            )
        };
        assert_eq!(env_bytes, &[0u8; 44]);
    }

    #[test]
    fn stores_the_full_error_word_unmodified() {
        let _guard = setup();

        for error in [0, 1, i32::MIN, -1, i32::MAX] {
            let mut validator = armed_validator();
            assert!(raise(&mut validator, error));
            assert_eq!(validator.prefix.error, error);
        }
    }

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

    #[test]
    fn raise_observes_the_error_store_before_leaving() {
        // Ordering probe distinct from the mock's panic: a validator whose
        // error field is pre-set to a sentinel must show the NEW error after
        // the call, proving the str precedes (not follows) the transfer.
        let _guard = setup();

        let mut validator = armed_validator();
        validator.prefix.error = -12345;
        assert!(raise(&mut validator, 0x55));
        assert_eq!(validator.prefix.error, 0x55);
    }
}
