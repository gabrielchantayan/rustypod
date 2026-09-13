//! Generic descriptor conversion — original: `FUN_0803b3b8` at load address
//! `0x0803b3b8` (176 bytes, `0x0803b3b8..0x0803b468`).
//!
//! Raw `osos.dec` has a distinct successor at `0x0803b468` (`mov r1,#0`),
//! confirming Ghidra's reported extent. Decoding every ARM `B`/`BL` immediate
//! finds exactly seven inbound direct `bl` calls, all unconditional, at
//! `0x0803a8e0`, `0x0803a944`, `0x0803b4f4`, `0x0805fd9c`, `0x080607ec`,
//! `0x08099c38`, and `0x08099c80`; there are no predicated forms. Four
//! unconditional `b` tail transfers at `0x082d38e0`, `0x082d38ec`,
//! `0x082d38f8`, and `0x082d3904` also enter this engine.
//!
//! The engine converts `source` under `descriptor`. If `output_slot` is NULL
//! or already holds a buffer, it makes one direct descriptor-engine call. An
//! empty output slot first asks the lower engine for a positive byte count;
//! it returns that non-positive result unchanged. It then allocates exactly
//! that many bytes through `traced_alloc(size, 0, 0)`, returning -1 without a
//! second conversion on allocation failure. On success it invokes the lower
//! engine with a local pointer to the allocated block, then stores the
//! original allocation in `*output_slot` even if that lower call changes its
//! local output pointer.
//!
//! Deliberate deviation: the lower descriptor engine at `0x0803b0a0` remains
//! unported. Target builds call that fixed address through the volatile ops
//! seam; hosts replace it with a recorder. `traced_alloc` is already ported
//! and remains a direct call.

use crate::drivers::ata_cmd::traced_alloc;
use core::ffi::c_void;

/// The three incoming registers preserved as the lower engine's frame.
/// `repr(C)` has the retail 12-byte layout on ARM; host recorders use their
/// native pointer-width layout and never expose this object to firmware.
#[repr(C)]
pub struct DescriptorConvertFrame {
    pub source: *mut u8,
    pub output_slot: *mut *mut u8,
    pub descriptor: *const u8,
}

/// ABI of the unported lower descriptor engine at `0x0803b0a0`.
pub type DescriptorConvertEngine = unsafe extern "C" fn(
    frame: *mut DescriptorConvertFrame,
    output: *mut *mut u8,
    descriptor: *const u8,
    limit: i32,
    state: *mut c_void,
) -> i32;

/// Calls outside this one-function port.
#[derive(Clone, Copy)]
pub struct GenericDescriptorConvertOps {
    pub engine: DescriptorConvertEngine,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_descriptor_convert_engine(
    frame: *mut DescriptorConvertFrame,
    output: *mut *mut u8,
    descriptor: *const u8,
    limit: i32,
    state: *mut c_void,
) -> i32 {
    let engine: DescriptorConvertEngine = unsafe { core::mem::transmute(0x0803_b0a0usize) };
    unsafe { engine(frame, output, descriptor, limit, state) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_descriptor_convert_engine(
    _frame: *mut DescriptorConvertFrame,
    _output: *mut *mut u8,
    _descriptor: *const u8,
    _limit: i32,
    _state: *mut c_void,
) -> i32 {
    panic!("generic_descriptor_convert requires descriptor engine 0x0803b0a0")
}

#[cfg(target_os = "none")]
pub const DEFAULT_GENERIC_DESCRIPTOR_CONVERT_OPS: GenericDescriptorConvertOps =
    GenericDescriptorConvertOps { engine: firmware_descriptor_convert_engine };
#[cfg(not(target_os = "none"))]
pub const DEFAULT_GENERIC_DESCRIPTOR_CONVERT_OPS: GenericDescriptorConvertOps =
    GenericDescriptorConvertOps { engine: missing_descriptor_convert_engine };

/// Target builds call the lower engine at `0x0803b0a0`; host tests replace
/// this volatile seam until that engine is independently ported.
pub static mut GENERIC_DESCRIPTOR_CONVERT_OPS: GenericDescriptorConvertOps =
    DEFAULT_GENERIC_DESCRIPTOR_CONVERT_OPS;

#[inline(always)]
fn generic_descriptor_convert_ops() -> GenericDescriptorConvertOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GENERIC_DESCRIPTOR_CONVERT_OPS)) }
}

/// Generic descriptor conversion — original: `FUN_0803b3b8` @ `0x0803b3b8`
/// (176 bytes; seven unconditional `bl` call sites).
///
/// # Safety
///
/// `source`, `output_slot`, and `descriptor` follow the unvalidated retail
/// descriptor-conversion ABI. `output_slot` may be NULL; a non-NULL slot must
/// be writable when it initially holds NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn generic_descriptor_convert(
    source: *mut u8,
    output_slot: *mut *mut u8,
    descriptor: *const u8,
) -> i32 {
    let mut frame = DescriptorConvertFrame { source, output_slot, descriptor };
    let engine = generic_descriptor_convert_ops().engine;

    if output_slot.is_null() || unsafe { !output_slot.read().is_null() } {
        return unsafe { engine(&mut frame, output_slot, descriptor, -1, core::ptr::null_mut()) };
    }

    let byte_count = unsafe { engine(&mut frame, core::ptr::null_mut(), descriptor, -1, core::ptr::null_mut()) };
    if byte_count <= 0 {
        return byte_count;
    }

    let allocation = unsafe { traced_alloc(byte_count, 0, 0) };
    if allocation.is_null() {
        return -1;
    }

    let mut converted = allocation;
    let result = unsafe { engine(&mut frame, &mut converted, descriptor, -1, core::ptr::null_mut()) };
    unsafe { output_slot.write(allocation) };
    result
}

#[cfg(test)]
use parking_lot::Mutex;

#[cfg(test)]
pub(crate) static GENERIC_DESCRIPTOR_CONVERT_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{missing_allocator, TracedAllocHooks, TRACED_ALLOC_HOOKS};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use core::ptr;

    static mut CALL_COUNT: usize = 0;
    static mut SOURCES: [usize; 2] = [0; 2];
    static mut OUTPUTS: [usize; 2] = [0; 2];
    static mut DESCRIPTORS: [usize; 2] = [0; 2];
    static mut LIMITS: [i32; 2] = [0; 2];
    static mut STATES: [usize; 2] = [0; 2];
    static mut RETURNS: [i32; 2] = [0; 2];
    static mut ALLOC_SIZE: i32 = 0;
    static mut ALLOCATION: [u8; 32] = [0; 32];

    const UPDATED_SOURCE: usize = 0x1f00_2000;
    const SCRIBBLED_OUTPUT: usize = 0x1f00_3000;

    unsafe extern "C" fn record_engine(
        frame: *mut DescriptorConvertFrame,
        output: *mut *mut u8,
        descriptor: *const u8,
        limit: i32,
        state: *mut c_void,
    ) -> i32 {
        unsafe {
            let call = CALL_COUNT;
            CALL_COUNT += 1;
            SOURCES[call] = (*frame).source as usize;
            OUTPUTS[call] = output as usize;
            DESCRIPTORS[call] = descriptor as usize;
            LIMITS[call] = limit;
            STATES[call] = state as usize;
            if call == 0 {
                (*frame).source = UPDATED_SOURCE as *mut u8;
            }
            if !output.is_null() {
                output.write(SCRIBBLED_OUTPUT as *mut u8);
            }
            RETURNS[call]
        }
    }

    unsafe extern "C" fn record_allocation(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        unsafe {
            assert_eq!((tag1, tag2), (0, 0));
            ALLOC_SIZE = size;
            ptr::addr_of_mut!(ALLOCATION).cast()
        }
    }

    struct EngineReset(GenericDescriptorConvertOps);

    impl Drop for EngineReset {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(GENERIC_DESCRIPTOR_CONVERT_OPS), self.0);
            }
        }
    }

    struct AllocatorReset(TracedAllocHooks);

    impl Drop for AllocatorReset {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(TRACED_ALLOC_HOOKS), self.0) }
        }
    }

    fn install_engine(results: [i32; 2]) -> EngineReset {
        unsafe {
            CALL_COUNT = 0;
            SOURCES = [0; 2];
            OUTPUTS = [0; 2];
            DESCRIPTORS = [0; 2];
            LIMITS = [0; 2];
            STATES = [0; 2];
            RETURNS = results;
            let previous = ptr::read_volatile(ptr::addr_of!(GENERIC_DESCRIPTOR_CONVERT_OPS));
            ptr::write_volatile(
                ptr::addr_of_mut!(GENERIC_DESCRIPTOR_CONVERT_OPS),
                GenericDescriptorConvertOps { engine: record_engine },
            );
            EngineReset(previous)
        }
    }

    fn install_allocator(allocator: TracedAllocHooks) -> AllocatorReset {
        unsafe {
            ALLOC_SIZE = 0;
            let previous = ptr::read_volatile(ptr::addr_of!(TRACED_ALLOC_HOOKS));
            ptr::write_volatile(ptr::addr_of_mut!(TRACED_ALLOC_HOOKS), allocator);
            AllocatorReset(previous)
        }
    }

    #[test]
    fn existing_output_bypasses_sizing_and_forwards_all_engine_arguments() {
        let _engine_guard = GENERIC_DESCRIPTOR_CONVERT_TEST_LOCK.lock();
        let _reset = install_engine([-0x351, 0]);
        let source = 0x1f00_1000usize as *mut u8;
        let descriptor = 0x1f00_4000usize as *const u8;
        let mut output = 0x1f00_5000usize as *mut u8;

        let result = unsafe { generic_descriptor_convert(source, &mut output, descriptor) };

        assert_eq!(result, -0x351);
        unsafe {
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(SOURCES[0], source as usize);
            assert_eq!(OUTPUTS[0], ptr::addr_of!(output) as usize);
            assert_eq!(DESCRIPTORS[0], descriptor as usize);
            assert_eq!(LIMITS[0], -1);
            assert_eq!(STATES[0], 0);
            assert_eq!(output as usize, SCRIBBLED_OUTPUT);
        }
    }

    #[test]
    fn empty_slot_sizes_allocates_and_keeps_original_allocation() {
        let _engine_guard = GENERIC_DESCRIPTOR_CONVERT_TEST_LOCK.lock();
        let _allocator_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _engine_reset = install_engine([13, -0x5b]);
        let _allocator_reset = install_allocator(TracedAllocHooks { alloc: record_allocation, trace: None });
        let source = 0x1f00_1000usize as *mut u8;
        let descriptor = 0x1f00_4000usize as *const u8;
        let mut output = ptr::null_mut();

        let result = unsafe { generic_descriptor_convert(source, &mut output, descriptor) };

        assert_eq!(result, -0x5b);
        unsafe {
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(SOURCES, [source as usize, UPDATED_SOURCE]);
            assert_eq!(OUTPUTS[0], 0);
            assert_ne!(OUTPUTS[1], 0);
            assert_eq!(DESCRIPTORS, [descriptor as usize; 2]);
            assert_eq!(LIMITS, [-1; 2]);
            assert_eq!(STATES, [0; 2]);
            assert_eq!(ALLOC_SIZE, 13);
            assert_eq!(output, ptr::addr_of_mut!(ALLOCATION).cast());
        }
    }

    #[test]
    fn allocation_failure_returns_minus_one_without_second_conversion() {
        let _engine_guard = GENERIC_DESCRIPTOR_CONVERT_TEST_LOCK.lock();
        let _allocator_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _engine_reset = install_engine([9, 0]);
        let _allocator_reset = install_allocator(TracedAllocHooks { alloc: missing_allocator, trace: None });
        let mut output = ptr::null_mut();

        let result = unsafe {
            generic_descriptor_convert(0x1f00_1000usize as *mut u8, &mut output, 0x1f00_4000usize as *const u8)
        };

        assert_eq!(result, -1);
        unsafe {
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(output, ptr::null_mut());
        }
    }
}
