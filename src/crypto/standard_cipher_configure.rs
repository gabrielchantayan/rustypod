//! Configures a proprietary `"STANDARD"` cipher operation.
//!
//! `standard_cipher_configure` — original: `FUN_0802a954` @ `0x0802a954`
//! (108 bytes, `0x0802a954..0x0802a9c0`; the next distinct function begins
//! at `0x0802a9c4`). Raw ARM decoding finds three inbound plain `bl` calls
//! (`0x0802a9ec`, `0x0802aa20`, and `0x0802aa88`), no predicated inbound
//! calls, and three unconditional body calls.
//!
//! It validates the cipher configuration. On success it expands the supplied
//! key into the caller's schedule buffer, then initializes the cipher context
//! with mode 8, the supplied round count, name, and auxiliary value. It
//! returns the validation status unchanged on failure and zero on success.
//!
//! # Deliberate deviations
//!
//! The three callees are not ported. On ARM this function calls their verified
//! retail entry points through absolute veneers; host tests replace those
//! targets with callbacks. This retains the verified ABI and control flow
//! without assigning unverified identities to the retail helpers.

/// ABI shared by the unported validation helper at `0x08027950`.
pub type RetailStandardCipherValidate = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32) -> u32;
/// ABI shared by the unported key-schedule helper at `0x0802dec0`.
pub type RetailStandardCipherExpandKey = unsafe extern "C" fn(u32, u32, u32, u32);
/// ABI shared by the unported context initializer at `0x0802e910`.
pub type RetailStandardCipherInitialize = unsafe extern "C" fn(u32, u32, u32, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_retail_standard_cipher_validate(
    _cipher_context: u32,
    _cipher_name: u32,
    _round_count: u32,
    _key_mode: u32,
    _configuration: u32,
    _auxiliary: u32,
) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_retail_standard_cipher_expand_key(
    _key_schedule: u32, _key_mode: u32, _round_count: u32, _cipher_context: u32,
) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_retail_standard_cipher_initialize(
    _cipher_context: u32, _mode: u32, _round_count: u32, _cipher_name: u32, _auxiliary: u32,
) {}

#[cfg(not(target_os = "none"))]
pub static mut RETAIL_STANDARD_CIPHER_VALIDATE: RetailStandardCipherValidate =
    missing_retail_standard_cipher_validate;
#[cfg(not(target_os = "none"))]
pub static mut RETAIL_STANDARD_CIPHER_EXPAND_KEY: RetailStandardCipherExpandKey =
    missing_retail_standard_cipher_expand_key;
#[cfg(not(target_os = "none"))]
pub static mut RETAIL_STANDARD_CIPHER_INITIALIZE: RetailStandardCipherInitialize =
    missing_retail_standard_cipher_initialize;

#[cfg(not(target_os = "none"))]
#[inline(never)]
unsafe fn retail_standard_cipher_validate(
    cipher_context: u32, cipher_name: u32, round_count: u32, key_mode: u32, configuration: u32,
    auxiliary: u32,
) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_STANDARD_CIPHER_VALIDATE))(
        cipher_context, cipher_name, round_count, key_mode, configuration, auxiliary,
    ) }
}
#[cfg(not(target_os = "none"))]
#[inline(never)]
unsafe fn retail_standard_cipher_expand_key(
    key_schedule: u32, key_mode: u32, round_count: u32, cipher_context: u32,
) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_STANDARD_CIPHER_EXPAND_KEY))(
        key_schedule, key_mode, round_count, cipher_context,
    ) }
}
#[cfg(not(target_os = "none"))]
#[inline(never)]
unsafe fn retail_standard_cipher_initialize(
    cipher_context: u32, mode: u32, round_count: u32, cipher_name: u32, auxiliary: u32,
) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_STANDARD_CIPHER_INITIALIZE))(
        cipher_context, mode, round_count, cipher_name, auxiliary,
    ) }
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn retail_standard_cipher_validate(
        cipher_context: u32, cipher_name: u32, round_count: u32, key_mode: u32,
        configuration: u32, auxiliary: u32,
    ) -> u32;
    fn retail_standard_cipher_expand_key(
        key_schedule: u32, key_mode: u32, round_count: u32, cipher_context: u32,
    );
    fn retail_standard_cipher_initialize(
        cipher_context: u32, mode: u32, round_count: u32, cipher_name: u32, auxiliary: u32,
    );
}
#[cfg(target_os = "none")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_standard_cipher_validate
retail_standard_cipher_validate:
    ldr pc, 1f
1:  .word 0x08027950
    .globl retail_standard_cipher_expand_key
retail_standard_cipher_expand_key:
    ldr pc, 1f
1:  .word 0x0802dec0
    .globl retail_standard_cipher_initialize
retail_standard_cipher_initialize:
    ldr pc, 1f
1:  .word 0x0802e910
"#);

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn standard_cipher_configure(
    key_schedule: u32,
    key_mode: u32,
    cipher_context: u32,
    cipher_name: u32,
    round_count: u32,
    configuration: u32,
    auxiliary: u32,
) -> u32 {
    let status = unsafe {
        retail_standard_cipher_validate(cipher_context, cipher_name, round_count, key_mode,
            configuration, auxiliary)
    };
    if status != 0 { return status; }
    unsafe {
        retail_standard_cipher_expand_key(key_schedule, key_mode, round_count, cipher_context);
        retail_standard_cipher_initialize(cipher_context, 8, round_count, configuration, auxiliary);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{RetailStandardCipherExpandKey, RetailStandardCipherInitialize,
        RetailStandardCipherValidate, RETAIL_STANDARD_CIPHER_EXPAND_KEY,
        RETAIL_STANDARD_CIPHER_INITIALIZE, RETAIL_STANDARD_CIPHER_VALIDATE,
        standard_cipher_configure};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut VALIDATE_ARGS: [u32; 6] = [0; 6];
    static mut EXPAND_ARGS: [u32; 4] = [0; 4];
    static mut INITIALIZE_ARGS: [u32; 5] = [0; 5];
    static mut STATUS: u32 = 0;

    unsafe extern "C" fn validate(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) -> u32 {
        unsafe { VALIDATE_ARGS = [a, b, c, d, e, f]; STATUS }
    }
    unsafe extern "C" fn expand(a: u32, b: u32, c: u32, d: u32) {
        unsafe { EXPAND_ARGS = [a, b, c, d]; }
    }
    unsafe extern "C" fn initialize(a: u32, b: u32, c: u32, d: u32, e: u32) {
        unsafe { INITIALIZE_ARGS = [a, b, c, d, e]; }
    }

    struct Restore(RetailStandardCipherValidate, RetailStandardCipherExpandKey, RetailStandardCipherInitialize);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            RETAIL_STANDARD_CIPHER_VALIDATE = self.0;
            RETAIL_STANDARD_CIPHER_EXPAND_KEY = self.1;
            RETAIL_STANDARD_CIPHER_INITIALIZE = self.2;
        } }
    }
    fn install() -> Restore { unsafe {
        let restore = Restore(RETAIL_STANDARD_CIPHER_VALIDATE, RETAIL_STANDARD_CIPHER_EXPAND_KEY,
            RETAIL_STANDARD_CIPHER_INITIALIZE);
        RETAIL_STANDARD_CIPHER_VALIDATE = validate;
        RETAIL_STANDARD_CIPHER_EXPAND_KEY = expand;
        RETAIL_STANDARD_CIPHER_INITIALIZE = initialize;
        VALIDATE_ARGS = [0; 6]; EXPAND_ARGS = [0; 4]; INITIALIZE_ARGS = [0; 5];
        restore
    } }

    #[test]
    fn success_forwards_all_words_and_configures_after_expansion() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install();
        unsafe { STATUS = 0; }
        assert_eq!(unsafe { standard_cipher_configure(1, 2, 3, 4, 5, 6, 7) }, 0);
        assert_eq!(unsafe { VALIDATE_ARGS }, [3, 4, 5, 2, 6, 7]);
        assert_eq!(unsafe { EXPAND_ARGS }, [1, 2, 5, 3]);
        assert_eq!(unsafe { INITIALIZE_ARGS }, [3, 8, 5, 6, 7]);
    }

    #[test]
    fn validation_failure_returns_status_without_mutating_cipher_state() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install();
        unsafe { STATUS = 11; }
        assert_eq!(unsafe { standard_cipher_configure(1, 2, 3, 4, 5, 6, 7) }, 11);
        assert_eq!(unsafe { EXPAND_ARGS }, [0; 4]);
        assert_eq!(unsafe { INITIALIZE_ARGS }, [0; 5]);
    }
}
