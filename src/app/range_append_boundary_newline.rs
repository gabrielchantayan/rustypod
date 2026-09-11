//! `range_append_and_preserve_boundary_newline` — original: `FUN_0811853c`
//! @ **0x0811853c** (52 bytes, `0x0811853c..0x08118570`; the separately
//! linked next function starts at `0x08118570`). Ghidra's reported 184-byte
//! extent incorrectly includes that sibling.
//!
//! A complete decode of every ARM `B`/`BL` immediate in `osos.dec` finds ten
//! direct `bl` call sites: nine unconditional and one `blne` at `0x081189b4`.
//! The predicated caller gates this append operation on its own prior condition;
//! this function contains no corresponding range NULL guard.
//!
//! # Algorithm
//!
//! Pass `range.start`, the wrapping difference `range.end - range.start`, and
//! `metadata` to the range append helper at `0x081195c4`; then return the result
//! of `0x08119160`, which conditionally preserves a newline at a range boundary.
//!
//! Deliberate deviation: both helpers remain unported. Target builds reach
//! their fixed addresses through payload-safe function pointers; host tests use
//! volatile dispatch operations. ARM codegen preserves the final tail transfer.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_APPEND_RANGE: usize = 0x0811_95c4;
const RETAIL_PRESERVE_BOUNDARY_NEWLINE: usize = 0x0811_9160;

/// Target-layout range descriptor. Only the start and end words are consumed.
#[repr(C)]
pub struct TextRange {
    pub unresolved_00: u32,
    pub start: u32,
    pub end: u32,
}

const _: [(); 12] = [(); core::mem::size_of::<TextRange>()];

/// ABI of `FUN_081195c4`, which appends a source span with metadata.
pub type AppendRange = unsafe extern "C" fn(*mut u8, u32, u32, u32);
/// ABI of `FUN_08119160`, which completes the range-boundary handling.
pub type PreserveBoundaryNewline = unsafe extern "C" fn(*mut u8, *const TextRange) -> u32;

/// Host/target dispatch operations for the two remaining retailOS helpers.
#[derive(Clone, Copy)]
pub struct RangeAppendBoundaryNewlineOps {
    pub append_range: AppendRange,
    pub preserve_boundary_newline: PreserveBoundaryNewline,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn append_range(context: *mut u8, start: u32, length: u32, metadata: u32) {
    let append: AppendRange = core::mem::transmute(RETAIL_APPEND_RANGE);
    append(context, start, length, metadata);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn preserve_boundary_newline(context: *mut u8, range: *const TextRange) -> u32 {
    let preserve: PreserveBoundaryNewline = core::mem::transmute(RETAIL_PRESERVE_BOUNDARY_NEWLINE);
    preserve(context, range)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_append_range(_context: *mut u8, _start: u32, _length: u32, _metadata: u32) {
    panic!("install range-append host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_preserve_boundary_newline(_context: *mut u8, _range: *const TextRange) -> u32 {
    panic!("install range-append host operations before calling this wrapper")
}

/// Host default before a test installs the retail helper equivalents.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_RANGE_APPEND_BOUNDARY_NEWLINE_OPS: RangeAppendBoundaryNewlineOps =
    RangeAppendBoundaryNewlineOps {
        append_range: missing_append_range,
        preserve_boundary_newline: missing_preserve_boundary_newline,
    };

/// Host-side seam. Target builds always call the retailOS helper addresses.
#[cfg(not(target_os = "none"))]
pub static mut RANGE_APPEND_BOUNDARY_NEWLINE_OPS: RangeAppendBoundaryNewlineOps =
    DEFAULT_RANGE_APPEND_BOUNDARY_NEWLINE_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn append_range(context: *mut u8, start: u32, length: u32, metadata: u32) {
    let ops = addr_of!(RANGE_APPEND_BOUNDARY_NEWLINE_OPS).read_volatile();
    (ops.append_range)(context, start, length, metadata);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn preserve_boundary_newline(context: *mut u8, range: *const TextRange) -> u32 {
    let ops = addr_of!(RANGE_APPEND_BOUNDARY_NEWLINE_OPS).read_volatile();
    (ops.preserve_boundary_newline)(context, range)
}

/// Appends `range` with `metadata`, then performs the retailOS newline-boundary
/// completion step.
///
/// # Safety
///
/// `range` must point to a readable, 12-byte target-layout [`TextRange`].
/// `context` and `metadata` must satisfy the unported append helper's contract.
/// RetailOS has no NULL guard for `range`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn range_append_and_preserve_boundary_newline(
    context: *mut u8,
    range: *const TextRange,
    metadata: u32,
) -> u32 {
    let range_ref = &*range;
    append_range(
        context,
        range_ref.start,
        range_ref.end.wrapping_sub(range_ref.start),
        metadata,
    );
    preserve_boundary_newline(context, range)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut APPEND_CALL: Option<(*mut u8, u32, u32, u32)> = None;
    static mut PRESERVE_CALL: *const TextRange = core::ptr::null();
    static mut ORDER: [u8; 2] = [0; 2];
    static mut ORDER_LEN: usize = 0;

    unsafe fn record_order(event: u8) {
        ORDER[ORDER_LEN] = event;
        ORDER_LEN += 1;
    }

    unsafe extern "C" fn record_append_range(
        context: *mut u8,
        start: u32,
        length: u32,
        metadata: u32,
    ) {
        APPEND_CALL = Some((context, start, length, metadata));
        record_order(1);
    }

    unsafe extern "C" fn record_preserve_boundary_newline(
        _context: *mut u8,
        range: *const TextRange,
    ) -> u32 {
        PRESERVE_CALL = range;
        record_order(2);
        0x71ce_b00c
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(APPEND_CALL).write(None);
            addr_of_mut!(PRESERVE_CALL).write(core::ptr::null());
            addr_of_mut!(ORDER).write([0; 2]);
            addr_of_mut!(ORDER_LEN).write(0);
            addr_of_mut!(RANGE_APPEND_BOUNDARY_NEWLINE_OPS).write(
                RangeAppendBoundaryNewlineOps {
                    append_range: record_append_range,
                    preserve_boundary_newline: record_preserve_boundary_newline,
                },
            );
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(RANGE_APPEND_BOUNDARY_NEWLINE_OPS)
                .write(DEFAULT_RANGE_APPEND_BOUNDARY_NEWLINE_OPS);
        }
        drop(guard);
    }

    #[test]
    fn forwards_wrapping_span_then_returns_boundary_helper_result() {
        let guard = install_recorder();
        let mut context = [0u8; 4];
        let range = TextRange {
            unresolved_00: 0,
            start: 0xffff_fff0,
            end: 0x0000_0010,
        };

        let result = unsafe {
            range_append_and_preserve_boundary_newline(
                context.as_mut_ptr(),
                addr_of!(range),
                0x5a17_0bad,
            )
        };

        unsafe {
            assert_eq!(
                addr_of!(APPEND_CALL).read(),
                Some((context.as_mut_ptr(), 0xffff_fff0, 0x20, 0x5a17_0bad))
            );
            assert_eq!(addr_of!(PRESERVE_CALL).read(), addr_of!(range));
            assert_eq!(addr_of!(ORDER).read(), [1, 2]);
        }
        assert_eq!(result, 0x71ce_b00c);
        restore_default(guard);
    }

    #[test]
    fn forwards_an_empty_range_without_skipping_either_helper() {
        let guard = install_recorder();
        let mut context = [0u8; 4];
        let range = TextRange {
            unresolved_00: u32::MAX,
            start: 0x0042_4242,
            end: 0x0042_4242,
        };

        unsafe {
            range_append_and_preserve_boundary_newline(context.as_mut_ptr(), addr_of!(range), 0);
            assert_eq!(
                addr_of!(APPEND_CALL).read(),
                Some((context.as_mut_ptr(), 0x0042_4242, 0, 0))
            );
            assert_eq!(addr_of!(PRESERVE_CALL).read(), addr_of!(range));
            assert_eq!(addr_of!(ORDER).read(), [1, 2]);
        }
        restore_default(guard);
    }
}
