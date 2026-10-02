//! Work-source readiness query — `FUN_0829b0d8` @ `0x0829b0d8`.
//!
//! True extent: 12 bytes, ending before the independent `mov r0, #0x8a00`
//! function at `0x0829b0e4`. Raw words: e5901000 e5911018 e12fff11.
//! Two plain inbound BLs (`0x08148598`, `0x081a7818`), zero predicated BLs;
//! the body has zero BLs and one indirect tail branch.
//!
//! Loads the source's first-word vtable and invokes slot +0x18 with the
//! unchanged source pointer, returning the full result word. Both observed
//! callers use zero/nonzero readiness; the virtual callee's identity remains
//! unresolved. Deliberate deviations: host vtables widen pointers structurally;
//! Rust expresses the tail dispatch as a final call. No result normalization,
//! NULL checks, or additional arguments are introduced.

#[cfg(target_os = "none")]
use super::record_work_pump::{WorkSourceTarget as WorkSource, WorkSourceHasWork};
#[cfg(not(target_os = "none"))]
use super::record_work_pump::HostWorkSource as WorkSource;

/// Query the source's virtual readiness slot without consuming its result.
///
/// # Safety
/// `source` must have a readable first-word vtable and a callable seventh slot
/// with the ABI `unsafe extern "C" fn(source) -> u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn work_source_query_readiness(source: *mut WorkSource) -> u32 {
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*source).vtable)) };
    #[cfg(target_os = "none")]
    {
        let entry = unsafe { core::ptr::read_volatile((vtable as *const u32).add(6)) };
        let query: WorkSourceHasWork = unsafe { core::mem::transmute(entry as usize) };
        unsafe { query(source) }
    }
    #[cfg(not(target_os = "none"))]
    unsafe { ((*vtable).has_work)(source) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_work_pump::HostWorkSourceVtable;

    #[repr(C)]
    struct Source {
        base: WorkSource,
        remaining: u32,
    }

    unsafe extern "C" fn remaining(source: *mut WorkSource) -> u32 {
        unsafe { (*source.cast::<Source>()).remaining }
    }

    unsafe extern "C" fn consume(source: *mut WorkSource) -> u32 {
        let source = unsafe { &mut *source.cast::<Source>() };
        let result = source.remaining;
        source.remaining = result.saturating_sub(1);
        result
    }

    #[test]
    fn preserves_full_readiness_word_and_observes_current_vtable() {
        let read_table = HostWorkSourceVtable { unresolved_00_14: [0; 6], has_work: remaining };
        let consume_table = HostWorkSourceVtable { unresolved_00_14: [0; 6], has_work: consume };
        let mut source = Source { base: WorkSource { vtable: &read_table }, remaining: 0 };
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            source.remaining = value;
            assert_eq!(unsafe { work_source_query_readiness(&mut source.base) }, value);
            assert_eq!(source.remaining, value);
        }
        source.remaining = 2;
        source.base.vtable = &consume_table;
        assert_eq!(unsafe { work_source_query_readiness(&mut source.base) }, 2);
        assert_eq!(source.remaining, 1);
        assert_eq!(unsafe { work_source_query_readiness(&mut source.base) }, 1);
        assert_eq!(unsafe { work_source_query_readiness(&mut source.base) }, 0);
        assert_eq!(source.remaining, 0);
    }
}
