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
//! Validation and key expansion retain verified retail entry-point veneers
//! with host callbacks. Context initialization now calls the Rust port in
//! `standard_cipher_initialize` directly.

use super::standard_cipher_initialize::standard_cipher_initialize;
/// ABI shared by the unported validation helper at `0x08027950`.
pub type RetailStandardCipherValidate = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32) -> u32;
/// ABI shared by the unported key-schedule helper at `0x0802dec0`.
pub type RetailStandardCipherExpandKey = unsafe extern "C" fn(*const u8, u32, u32, *mut u8);

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
    _key_schedule: *const u8, _key_mode: u32, _round_count: u32, _cipher_context: *mut u8,
) {}

#[cfg(not(target_os = "none"))]
pub static mut RETAIL_STANDARD_CIPHER_VALIDATE: RetailStandardCipherValidate =
    missing_retail_standard_cipher_validate;
#[cfg(not(target_os = "none"))]
pub static mut RETAIL_STANDARD_CIPHER_EXPAND_KEY: RetailStandardCipherExpandKey =
    missing_retail_standard_cipher_expand_key;

#[cfg(test)]
pub(super) static EXPANSION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
extern crate std;

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
pub(super) unsafe fn retail_standard_cipher_expand_key(
    key_schedule: *const u8, key_mode: u32, round_count: u32, cipher_context: *mut u8,
) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_STANDARD_CIPHER_EXPAND_KEY))(
        key_schedule, key_mode, round_count, cipher_context,
    ) }
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn retail_standard_cipher_validate(
        cipher_context: u32, cipher_name: u32, round_count: u32, key_mode: u32,
        configuration: u32, auxiliary: u32,
    ) -> u32;
    pub(super) fn retail_standard_cipher_expand_key(
        key_schedule: *const u8, key_mode: u32, round_count: u32, cipher_context: *mut u8,
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
        retail_standard_cipher_expand_key(key_schedule as *const u8, key_mode, round_count,
            cipher_context as *mut u8);
        standard_cipher_initialize(cipher_context as *mut u32, 8, round_count,
            configuration as *const u8, auxiliary);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{RetailStandardCipherExpandKey, RetailStandardCipherValidate,
        RETAIL_STANDARD_CIPHER_EXPAND_KEY, RETAIL_STANDARD_CIPHER_VALIDATE,
        standard_cipher_configure};
    extern crate std;

    unsafe extern "C" fn reject(_: u32, _: u32, _: u32, _: u32, _: u32, _: u32) -> u32 { 11 }
    unsafe extern "C" fn unexpected_expansion(_: *const u8, _: u32, _: u32, _: *mut u8) {
        panic!("rejected configuration must not expand the key");
    }
    struct Restore(RetailStandardCipherValidate, RetailStandardCipherExpandKey);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            RETAIL_STANDARD_CIPHER_VALIDATE = self.0;
            RETAIL_STANDARD_CIPHER_EXPAND_KEY = self.1;
        } }
    }

    #[test]
    fn validation_failure_returns_status_without_accessing_cipher_state() {
        let _lock = super::EXPANSION_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _restore = unsafe {
            let restore = Restore(RETAIL_STANDARD_CIPHER_VALIDATE, RETAIL_STANDARD_CIPHER_EXPAND_KEY);
            RETAIL_STANDARD_CIPHER_VALIDATE = reject;
            RETAIL_STANDARD_CIPHER_EXPAND_KEY = unexpected_expansion;
            restore
        };
        assert_eq!(unsafe { standard_cipher_configure(0, 2, 0, 0, 5, 0, 7) }, 11);
    }
}
