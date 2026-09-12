//! Opaque descriptor conversion — original: `FUN_082d38f4` @ load address
//! `0x082d38f4` (**12 bytes**, not Ghidra's reported 8). Raw `osos.dec`
//! decoding proves the extent: the two instructions are followed by the
//! function-local descriptor literal at `0x082d38fc`; the separately linked
//! sibling starts at `0x082d3900`.
//!
//! ```text
//! 082d38f4  ldr r2, [pc]        @ 0x089063e8
//! 082d38f8  b   0x0803b3b8
//! 082d38fc  .word 0x089063e8
//! ```
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds exactly **eight
//! direct `bl` calls**, all unconditional: `0x080af15c`, `0x080af16c`,
//! `0x080af270`, `0x080af280`, `0x08272a84`, `0x08272aac`, `0x082d4694`, and
//! `0x082d46a4`. There are no predicated calls or tail branches. No aligned
//! data word contains this wrapper's address, so it is not evidence of a
//! virtual dispatch target.
//!
//! The wrapper supplies the fixed opaque descriptor `0x089063e8` as r2 and
//! tail-branches to the generic descriptor conversion engine at `0x0803b3b8`,
//! forwarding its source and optional output-slot arguments and returning the
//! engine's result unchanged. The descriptor's concrete type and the generic
//! engine are not ported; their identities are therefore deliberately not
//! invented.
//!
//! Deliberate deviation: none on ARM, where global assembly retains all three
//! raw words and the tail edge. Hosts use a replaceable conversion-engine seam
//! because the retail engine address is unmapped.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

/// Fixed opaque descriptor loaded into r2 by the wrapper.
pub const OPAQUE_DESCRIPTOR_CONVERT_DESCRIPTOR: usize = 0x0890_63e8;

/// ABI of the unported generic descriptor conversion engine at `0x0803b3b8`.
pub type OpaqueDescriptorConvertEngine =
    unsafe extern "C" fn(source: *mut u8, output_slot: *mut *mut u8, descriptor: *const u8) -> i32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_opaque_descriptor_convert_engine(
    _source: *mut u8,
    _output_slot: *mut *mut u8,
    _descriptor: *const u8,
) -> i32 {
    panic!("opaque descriptor conversion engine is unavailable on the host")
}

/// Host seam for the unported generic descriptor conversion engine.
#[cfg(not(target_arch = "arm"))]
pub static mut OPAQUE_DESCRIPTOR_CONVERT_ENGINE: OpaqueDescriptorConvertEngine =
    missing_opaque_descriptor_convert_engine;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn descriptor_convert_engine() -> OpaqueDescriptorConvertEngine {
    unsafe { ptr::read_volatile(ptr::addr_of!(OPAQUE_DESCRIPTOR_CONVERT_ENGINE)) }
}

#[cfg(target_arch = "arm")]
extern "C" {
    /// opaque_descriptor_convert — original: `FUN_082d38f4` @ `0x082d38f4`
    /// (12 bytes; eight direct, unconditional `bl` call sites).
    pub fn opaque_descriptor_convert(source: *mut u8, output_slot: *mut *mut u8) -> i32;
}

/// Invokes the generic conversion engine with this wrapper's fixed descriptor.
///
/// # Safety
///
/// `source` and `output_slot` follow the unvalidated ABI of the unported
/// descriptor conversion engine. `output_slot` may be NULL; the wrapper does
/// not inspect either argument.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_descriptor_convert(
    source: *mut u8,
    output_slot: *mut *mut u8,
) -> i32 {
    unsafe {
        descriptor_convert_engine()(source, output_slot, OPAQUE_DESCRIPTOR_CONVERT_DESCRIPTOR as *const u8)
    }
}

// A Rust call would add a local return edge. Preserve the retail `b` exactly.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.opaque_descriptor_convert, "ax", %progbits
    .p2align 2
    .globl opaque_descriptor_convert
    .type opaque_descriptor_convert, %function
opaque_descriptor_convert:
    ldr     r2, [pc]
    b       0x0803b3b8
    .word   0x089063e8
    .size opaque_descriptor_convert, . - opaque_descriptor_convert
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static ENGINE_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_COUNT: u32 = 0;
    static mut RECORDED_SOURCE: usize = usize::MAX;
    static mut RECORDED_OUTPUT_SLOT: usize = usize::MAX;
    static mut RECORDED_DESCRIPTOR: usize = 0;

    unsafe extern "C" fn record_convert(
        source: *mut u8,
        output_slot: *mut *mut u8,
        descriptor: *const u8,
    ) -> i32 {
        unsafe {
            CALL_COUNT += 1;
            RECORDED_SOURCE = source as usize;
            RECORDED_OUTPUT_SLOT = output_slot as usize;
            RECORDED_DESCRIPTOR = descriptor as usize;
        }
        -0x351
    }

    struct EngineReset(OpaqueDescriptorConvertEngine);

    impl Drop for EngineReset {
        fn drop(&mut self) {
            unsafe { OPAQUE_DESCRIPTOR_CONVERT_ENGINE = self.0 };
        }
    }

    fn install_recorder() -> EngineReset {
        unsafe {
            CALL_COUNT = 0;
            RECORDED_SOURCE = usize::MAX;
            RECORDED_OUTPUT_SLOT = usize::MAX;
            RECORDED_DESCRIPTOR = 0;
            let previous = ptr::read_volatile(addr_of!(OPAQUE_DESCRIPTOR_CONVERT_ENGINE));
            OPAQUE_DESCRIPTOR_CONVERT_ENGINE = record_convert;
            EngineReset(previous)
        }
    }

    #[test]
    fn null_arguments_are_forwarded_without_wrapper_guards() {
        let _guard = ENGINE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = install_recorder();

        let result = unsafe { opaque_descriptor_convert(ptr::null_mut(), ptr::null_mut()) };

        assert_eq!(result, -0x351);
        unsafe {
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(RECORDED_SOURCE, 0);
            assert_eq!(RECORDED_OUTPUT_SLOT, 0);
            assert_eq!(RECORDED_DESCRIPTOR, OPAQUE_DESCRIPTOR_CONVERT_DESCRIPTOR);
        }
    }

    #[test]
    fn forwards_nonnull_source_and_output_slot_with_fixed_descriptor() {
        let _guard = ENGINE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = install_recorder();
        let source = 0x2a4c_1000usize as *mut u8;
        let output_slot = 0x2a4c_2000usize as *mut *mut u8;

        let result = unsafe { opaque_descriptor_convert(source, output_slot) };

        assert_eq!(result, -0x351);
        unsafe {
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(RECORDED_SOURCE, source as usize);
            assert_eq!(RECORDED_OUTPUT_SLOT, output_slot as usize);
            assert_eq!(RECORDED_DESCRIPTOR, OPAQUE_DESCRIPTOR_CONVERT_DESCRIPTOR);
        }
    }
}
