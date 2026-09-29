//! Opaque descriptor conversion — original: `FUN_082d38dc` @ load address
//! `0x082d38dc` (12 bytes: 8 bytes of code plus its function-local literal at
//! `0x082d38e4`). Raw `osos.dec` decoding proves the extent: the next real
//! function starts at `0x082d38e8` with `ldr r2, [pc]`.
//!
//! ```text
//! 082d38dc  ldr r2, [pc]        @ 0x089062ec
//! 082d38e0  b   0x0803b3b8
//! 082d38e4  .word 0x089062ec
//! ```
//!
//! Complete-image A32 branch decoding finds exactly two direct `bl` calls,
//! both unconditional, at `0x080eb9f8` and `0x080eba20`; there are no
//! predicated `bl` calls or inbound tail branches. The wrapper supplies fixed
//! descriptor `0x089062ec` in r2, tail-branches to generic descriptor
//! conversion, and preserves source, output slot, and its result unchanged.
//!
//! Deliberate deviation: none on ARM, where global assembly retains the raw
//! tail edge. Hosts call the generic conversion port through its recorder seam.

#[cfg(not(target_arch = "arm"))]
use crate::cxx::generic_descriptor_convert::generic_descriptor_convert;

/// Fixed opaque descriptor loaded into r2 by the wrapper.
pub const OPAQUE_DESCRIPTOR_CONVERT_089062EC_DESCRIPTOR: usize = 0x0890_62ec;

#[cfg(target_arch = "arm")]
extern "C" {
    /// opaque_descriptor_convert_089062ec — original: `FUN_082d38dc` @ `0x082d38dc`
    /// (12 bytes; two direct, unconditional `bl` call sites).
    pub fn opaque_descriptor_convert_089062ec(source: *mut u8, output_slot: *mut *mut u8) -> i32;
}

/// Invokes generic descriptor conversion with this wrapper's fixed descriptor.
///
/// # Safety
///
/// `source` and `output_slot` follow the unvalidated descriptor-conversion ABI.
/// `output_slot` may be NULL; the wrapper does not inspect either argument.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_descriptor_convert_089062ec(
    source: *mut u8,
    output_slot: *mut *mut u8,
) -> i32 {
    unsafe {
        generic_descriptor_convert(
            source,
            output_slot,
            OPAQUE_DESCRIPTOR_CONVERT_089062EC_DESCRIPTOR as *const u8,
        )
    }
}

// A Rust call would add a local return edge. Preserve the retail `b` exactly.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.opaque_descriptor_convert_089062ec, "ax", %progbits
    .p2align 2
    .globl opaque_descriptor_convert_089062ec
    .type opaque_descriptor_convert_089062ec, %function
opaque_descriptor_convert_089062ec:
    ldr     r2, [pc]
    b       generic_descriptor_convert
    .word   0x089062ec
    .size opaque_descriptor_convert_089062ec, . - opaque_descriptor_convert_089062ec
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::generic_descriptor_convert::{
        DescriptorConvertEngine, DescriptorConvertFrame, GenericDescriptorConvertOps,
        GENERIC_DESCRIPTOR_CONVERT_OPS, GENERIC_DESCRIPTOR_CONVERT_TEST_LOCK,
    };
    use core::ptr;

    static mut CALL_COUNT: u32 = 0;
    static mut RECORDED_SOURCE: usize = usize::MAX;
    static mut RECORDED_OUTPUT_SLOT: usize = usize::MAX;
    static mut RECORDED_DESCRIPTOR: usize = 0;

    unsafe extern "C" fn record_convert(
        frame: *mut DescriptorConvertFrame,
        output_slot: *mut *mut u8,
        descriptor: *const u8,
        limit: i32,
        state: *mut core::ffi::c_void,
    ) -> i32 {
        unsafe {
            assert_eq!(limit, -1);
            assert!(state.is_null());
            CALL_COUNT += 1;
            RECORDED_SOURCE = (*frame).source as usize;
            RECORDED_OUTPUT_SLOT = output_slot as usize;
            RECORDED_DESCRIPTOR = descriptor as usize;
        }
        -0x351
    }

    struct EngineReset(DescriptorConvertEngine);

    impl Drop for EngineReset {
        fn drop(&mut self) {
            unsafe {
                GENERIC_DESCRIPTOR_CONVERT_OPS = GenericDescriptorConvertOps { engine: self.0 };
            }
        }
    }

    fn install_recorder() -> EngineReset {
        unsafe {
            CALL_COUNT = 0;
            RECORDED_SOURCE = usize::MAX;
            RECORDED_OUTPUT_SLOT = usize::MAX;
            RECORDED_DESCRIPTOR = 0;
            let previous = ptr::read_volatile(ptr::addr_of!(GENERIC_DESCRIPTOR_CONVERT_OPS)).engine;
            GENERIC_DESCRIPTOR_CONVERT_OPS = GenericDescriptorConvertOps { engine: record_convert };
            EngineReset(previous)
        }
    }

    #[test]
    fn null_arguments_are_forwarded_without_wrapper_guards() {
        let _engine_guard = GENERIC_DESCRIPTOR_CONVERT_TEST_LOCK.lock();
        let _reset = install_recorder();

        let result = unsafe { opaque_descriptor_convert_089062ec(ptr::null_mut(), ptr::null_mut()) };

        assert_eq!(result, -0x351);
        unsafe {
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(RECORDED_SOURCE, 0);
            assert_eq!(RECORDED_OUTPUT_SLOT, 0);
            assert_eq!(RECORDED_DESCRIPTOR, OPAQUE_DESCRIPTOR_CONVERT_089062EC_DESCRIPTOR);
        }
    }

    #[test]
    fn forwards_nonnull_source_and_output_slot_with_fixed_descriptor() {
        let _engine_guard = GENERIC_DESCRIPTOR_CONVERT_TEST_LOCK.lock();
        let _reset = install_recorder();
        let source = 0x2a4c_1000usize as *mut u8;
        let mut output = 0x2a4c_2000usize as *mut u8;

        let result = unsafe { opaque_descriptor_convert_089062ec(source, &mut output) };

        assert_eq!(result, -0x351);
        unsafe {
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(RECORDED_SOURCE, source as usize);
            assert_eq!(RECORDED_OUTPUT_SLOT, ptr::addr_of!(output) as usize);
            assert_eq!(RECORDED_DESCRIPTOR, OPAQUE_DESCRIPTOR_CONVERT_089062EC_DESCRIPTOR);
        }
    }
}
