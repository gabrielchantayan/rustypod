//! Formatter veneer for the retailOS descriptor-based formatting family.
//!
//! Port: `format_with_descriptor` — `FUN_080caab4` @ **0x080caab4** (104
//! bytes, `0x080caab4..0x080cab1c`). Binary-decoding every ARM `B`/`BL` word
//! in `osos.dec` finds eight inbound calls: `0x080dac00`, `0x080dac2c`,
//! `0x081095a8`, `0x0810a4a8`, `0x0812815c`, `0x08175490`, `0x081e92b8`, and
//! `0x08299e48`. All eight are unconditional `bl`; there are no predicated
//! calls or tail branches to this entry.
//!
//! The veneer first normalizes its opaque argument descriptor through
//! `0x08075ff0` into nine words of stack storage. On a nonzero normalization
//! result, it invokes the descriptor formatter at `0x080ac954`, forwarding
//! destination, capacity, format, normalized descriptor, and context. A
//! nonzero formatter result passes through. Every other path returns zero;
//! when capacity is nonzero it also writes the required empty-string NUL at
//! `destination[0]`.
//!
//! Deliberate deviation: none on target. The two unported callees use typed,
//! volatile dispatch slots so host tests can prove this veneer while target
//! builds continue to call the stock functions in place.

use core::{ffi::c_void, mem::MaybeUninit};

/// The 36-byte normalized descriptor `FUN_08075ff0` produces on its caller's
/// stack. Its fields belong to the unported formatter, so they remain opaque.
pub type FormatDescriptor = [u32; 9];

/// Normalizes the caller-owned descriptor into the formatter's nine-word form.
pub type FormatDescriptorBuildFn =
    unsafe extern "C" fn(source: *const c_void, output: *mut FormatDescriptor) -> i32;

/// The unported descriptor formatter at `0x080ac954`.
pub type DescriptorFormatCoreFn = unsafe extern "C" fn(
    destination: *mut u8,
    capacity: u32,
    format: *const u8,
    descriptor: *const FormatDescriptor,
    context: *const c_void,
) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_build_format_descriptor(
    source: *const c_void,
    output: *mut FormatDescriptor,
) -> i32 {
    let worker: FormatDescriptorBuildFn = unsafe { core::mem::transmute(0x0807_5ff0usize) };
    unsafe { worker(source, output) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_build_format_descriptor(
    _source: *const c_void,
    _output: *mut FormatDescriptor,
) -> i32 {
    panic!("format_with_descriptor requires descriptor builder 0x08075ff0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_descriptor_format_core(
    destination: *mut u8,
    capacity: u32,
    format: *const u8,
    descriptor: *const FormatDescriptor,
    context: *const c_void,
) -> i32 {
    let worker: DescriptorFormatCoreFn = unsafe { core::mem::transmute(0x080a_c954usize) };
    unsafe { worker(destination, capacity, format, descriptor, context) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_descriptor_format_core(
    _destination: *mut u8,
    _capacity: u32,
    _format: *const u8,
    _descriptor: *const FormatDescriptor,
    _context: *const c_void,
) -> i32 {
    panic!("format_with_descriptor requires formatter core 0x080ac954")
}

/// Active descriptor normalizer. The target default is the stock worker;
/// host tests install recording workers.
#[cfg(target_os = "none")]
pub static mut FORMAT_DESCRIPTOR_BUILD: FormatDescriptorBuildFn = firmware_build_format_descriptor;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut FORMAT_DESCRIPTOR_BUILD: FormatDescriptorBuildFn = missing_build_format_descriptor;

/// Active descriptor formatter. The target default is the stock worker;
/// host tests install recording workers.
#[cfg(target_os = "none")]
pub static mut DESCRIPTOR_FORMAT_CORE: DescriptorFormatCoreFn = firmware_descriptor_format_core;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut DESCRIPTOR_FORMAT_CORE: DescriptorFormatCoreFn = missing_descriptor_format_core;

#[inline(always)]
unsafe fn descriptor_builder() -> FormatDescriptorBuildFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(FORMAT_DESCRIPTOR_BUILD)) }
}

#[inline(always)]
unsafe fn descriptor_format_core() -> DescriptorFormatCoreFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DESCRIPTOR_FORMAT_CORE)) }
}

/// `format_with_descriptor` — original: `FUN_080caab4` @ 0x080caab4 (104
/// bytes; 8 unconditional `bl` call sites, binary-verified).
///
/// Converts `arguments` into the formatter's opaque nine-word descriptor and
/// formats `format` into `destination` through the stock descriptor core. A
/// nonzero core result returns unchanged. Failed normalization and a zero core
/// result both return zero and, when `capacity != 0`, clear `destination[0]`.
/// The original has no pointer guards: `destination` must be writable whenever
/// `capacity != 0`; all other pointer validity belongs to its respective
/// worker.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn format_with_descriptor(
    destination: *mut u8,
    capacity: u32,
    format: *const u8,
    arguments: *const c_void,
    context: *const c_void,
) -> i32 {
    // The raw builder writes every word before the core can observe it; the
    // stock frame leaves this storage uninitialized too.
    let mut descriptor = MaybeUninit::<FormatDescriptor>::uninit();
    if unsafe { descriptor_builder()(arguments, descriptor.as_mut_ptr()) } != 0 {
        let result = unsafe {
            descriptor_format_core()(destination, capacity, format, descriptor.as_ptr(), context)
        };
        if result != 0 {
            return result;
        }
    }

    if capacity != 0 {
        unsafe { destination.write(0) };
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut BUILD_RESULT: i32 = 1;
    static mut CORE_RESULT: i32 = 0;
    static mut BUILD_CALLS: u32 = 0;
    static mut CORE_CALLS: u32 = 0;
    static mut BUILD_SOURCE: *const c_void = core::ptr::null();
    static mut CORE_DESTINATION: *mut u8 = core::ptr::null_mut();
    static mut CORE_CAPACITY: u32 = 0;
    static mut CORE_FORMAT: *const u8 = core::ptr::null();
    static mut CORE_DESCRIPTOR: FormatDescriptor = [0; 9];
    static mut CORE_CONTEXT: *const c_void = core::ptr::null();

    unsafe extern "C" fn recording_builder(
        source: *const c_void,
        output: *mut FormatDescriptor,
    ) -> i32 {
        unsafe {
            BUILD_CALLS += 1;
            BUILD_SOURCE = source;
            output.write([0x1020_3040, 1, 2, 3, 4, 5, 6, 7, 8]);
            BUILD_RESULT
        }
    }

    unsafe extern "C" fn recording_core(
        destination: *mut u8,
        capacity: u32,
        format: *const u8,
        descriptor: *const FormatDescriptor,
        context: *const c_void,
    ) -> i32 {
        unsafe {
            CORE_CALLS += 1;
            CORE_DESTINATION = destination;
            CORE_CAPACITY = capacity;
            CORE_FORMAT = format;
            CORE_DESCRIPTOR = descriptor.read();
            CORE_CONTEXT = context;
            CORE_RESULT
        }
    }

    struct SeamGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(FORMAT_DESCRIPTOR_BUILD).write(missing_build_format_descriptor);
                core::ptr::addr_of_mut!(DESCRIPTOR_FORMAT_CORE).write(missing_descriptor_format_core);
            }
        }
    }

    fn install(build_result: i32, core_result: i32) -> SeamGuard {
        let guard = SEAM_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            BUILD_RESULT = build_result;
            CORE_RESULT = core_result;
            BUILD_CALLS = 0;
            CORE_CALLS = 0;
            BUILD_SOURCE = core::ptr::null();
            CORE_DESTINATION = core::ptr::null_mut();
            CORE_CAPACITY = 0;
            CORE_FORMAT = core::ptr::null();
            CORE_DESCRIPTOR = [0; 9];
            CORE_CONTEXT = core::ptr::null();
            core::ptr::addr_of_mut!(FORMAT_DESCRIPTOR_BUILD).write(recording_builder);
            core::ptr::addr_of_mut!(DESCRIPTOR_FORMAT_CORE).write(recording_core);
        }
        SeamGuard(guard)
    }

    #[test]
    fn forwards_a_normalized_descriptor_and_nonzero_core_result() {
        let _guard = install(1, -17);
        let mut destination = [0xa5u8; 8];
        let format = b"%T: %d\0";
        let arguments = [0x0809_0000u32, 42];
        let context = [0u32; 1];

        let result = unsafe {
            format_with_descriptor(
                destination.as_mut_ptr(),
                destination.len() as u32,
                format.as_ptr(),
                arguments.as_ptr().cast(),
                context.as_ptr().cast(),
            )
        };

        assert_eq!(result, -17);
        assert_eq!(unsafe { BUILD_CALLS }, 1);
        assert_eq!(unsafe { CORE_CALLS }, 1);
        assert_eq!(unsafe { BUILD_SOURCE }, arguments.as_ptr().cast());
        assert_eq!(unsafe { CORE_DESTINATION }, destination.as_mut_ptr());
        assert_eq!(unsafe { CORE_CAPACITY }, destination.len() as u32);
        assert_eq!(unsafe { CORE_FORMAT }, format.as_ptr());
        assert_eq!(unsafe { CORE_DESCRIPTOR }, [0x1020_3040, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(unsafe { CORE_CONTEXT }, context.as_ptr().cast());
        assert_eq!(destination, [0xa5; 8], "a nonzero core result does not force a terminator");
    }

    #[test]
    fn zero_core_result_clears_a_nonempty_destination() {
        let _guard = install(1, 0);
        let mut destination = [0x5au8; 3];

        let result = unsafe {
            format_with_descriptor(
                destination.as_mut_ptr(),
                destination.len() as u32,
                b"text\0".as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };

        assert_eq!(result, 0);
        assert_eq!(unsafe { CORE_CALLS }, 1);
        assert_eq!(destination, [0, 0x5a, 0x5a]);
    }

    #[test]
    fn failed_descriptor_build_skips_the_core_and_clears_destination() {
        let _guard = install(0, 91);
        let mut destination = [0x9cu8; 2];

        let result = unsafe {
            format_with_descriptor(
                destination.as_mut_ptr(),
                2,
                b"unused\0".as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };

        assert_eq!(result, 0);
        assert_eq!(unsafe { BUILD_CALLS }, 1);
        assert_eq!(unsafe { CORE_CALLS }, 0);
        assert_eq!(destination, [0, 0x9c]);
    }

    #[test]
    fn zero_capacity_passes_through_but_never_writes_destination() {
        let _guard = install(1, 0);

        let result = unsafe {
            format_with_descriptor(
                core::ptr::null_mut(),
                0,
                b"\0".as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };

        assert_eq!(result, 0);
        assert_eq!(unsafe { CORE_CALLS }, 1, "the zero capacity only gates final NUL storage");
        assert!(unsafe { CORE_DESTINATION }.is_null());
        assert_eq!(unsafe { CORE_CAPACITY }, 0);
    }
}
