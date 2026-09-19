//! OpenSSL memory-BIO method factory.
//!
//! Port: [`bio_s_mem`] — `FUN_0803d8a8` @ **0x0803d8a8** (**8 bytes**,
//! `0x0803d8a8..0x0803d8b0`; the successor begins at 0x0803d8b4 after this
//! veneer’s literal word). Raw decoding found **4 plain `bl` call sites**:
//! `0x08060308`, `0x082728f4`, `0x082d44b4`, and `0x082d45ac`; there are no
//! predicated calls.
//!
//! # Algorithm
//!
//! Loads and returns the fixed `BIO_METHOD` object at 0x08a0c27c. It is the
//! memory-method factory used with the base64-filter factory at 0x0803d358.
//!
//! # Deliberate deviations
//!
//! None. The target implementation is the original two instructions and
//! literal word; the host implementation returns that same address for tests.

#[cfg(not(target_os = "none"))]
use super::bio_ctrl::BioMethod;

#[cfg(not(target_os = "none"))]
const MEMORY_BIO_METHOD: usize = 0x08a0_c27c;
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.bio_s_mem,"ax",%progbits
    .globl bio_s_mem
    .type bio_s_mem,%function
bio_s_mem:
    ldr r0, [pc]
    bx lr
    .size bio_s_mem, . - bio_s_mem
    .word 0x08a0c27c
"#
);

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn bio_s_mem() -> *mut BioMethod {
    MEMORY_BIO_METHOD as *mut BioMethod
}

#[cfg(test)]
mod tests {
    use super::{bio_s_mem, MEMORY_BIO_METHOD};

    #[test]
    fn returns_the_fixed_memory_method_on_every_call() {
        let first = unsafe { bio_s_mem() };
        let second = unsafe { bio_s_mem() };

        assert_eq!(first as usize, MEMORY_BIO_METHOD);
        assert_eq!(second, first);
    }
}
