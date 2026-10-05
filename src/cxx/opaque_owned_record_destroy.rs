//! `opaque_owned_record_destroy` — original: `FUN_083d3940` @ `0x083d3940`.
//!
//! Raw ARM words establish the exact 40-byte extent `0x083d3940..0x083d3967`:
//! the following `push {r4,r5,r6,r7,r8,r9,sl,lr}` starts an independent
//! function. Whole-image A32 decoding finds two inbound plain `bl` sites and
//! no predicated inbound `bl` sites. The body has one predicated `blne` to
//! `operator_delete_tag3` @ `0x082aad14`, then tail-branches to the ported
//! `opaque_owned_record_cleanup` @ `0x081bb7a8`.
//!
//! The five target-width words are an opaque record. If word 4 is nonzero,
//! its owned word-1 allocation is released when nonzero; the record is then
//! passed unchanged to the cleanup helper. Rust calls the ported cleanup;
//! host tests substitute only the allocator.

use crate::heap::veneers::operator_delete_tag3;

use super::opaque_owned_record_cleanup::opaque_owned_record_cleanup;

#[cfg(target_os = "none")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_owned_record_destroy(record: *mut u32) -> *mut u32 {
    unsafe { opaque_owned_record_destroy_with(record, operator_delete_tag3) }
}

#[inline(always)]
unsafe fn opaque_owned_record_destroy_with(
    record: *mut u32,
    dealloc: unsafe extern "C" fn(*mut u8),
) -> *mut u32 {
    if unsafe { record.add(4).read() } != 0 {
        let allocation = unsafe { record.add(1).read() };
        if allocation != 0 {
            unsafe { dealloc(allocation as usize as *mut u8) };
        }
    }
    unsafe { opaque_owned_record_cleanup(record) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    static mut DEALLOCATED: u32 = 0;

    unsafe extern "C" fn record_dealloc(allocation: *mut u8) {
        unsafe { DEALLOCATED = allocation as usize as u32 };
    }


    #[test]
    fn releases_owned_allocation_before_cleanup() {
        let _lock = crate::util::video_engine::LOCK.lock();
        let Some(record) = try_map_u32_slab(hints::CXX_OPAQUE_OWNED_RECORD_DESTROY, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/opaque_owned_record_destroy"));
            return;
        };
        unsafe {
            record.cast::<u32>().add(1).write(record.add(0x100) as usize as u32);
            record.cast::<u32>().add(4).write(1);
            DEALLOCATED = 0;
            crate::util::video_engine::set_mock_instance(core::ptr::null_mut());
            assert_eq!(opaque_owned_record_destroy_with(record.cast(), record_dealloc), record.cast());
            assert_eq!(DEALLOCATED, record.add(0x100) as usize as u32);
        }
    }

    #[test]
    fn skips_absent_owned_allocation_but_always_cleans_up() {
        let _lock = crate::util::video_engine::LOCK.lock();
        let Some(record) = try_map_u32_slab(hints::CXX_OPAQUE_OWNED_RECORD_DESTROY, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/opaque_owned_record_destroy"));
            return;
        };
        unsafe {
            record.cast::<u32>().add(1).write(record.add(0x100) as usize as u32);
            record.cast::<u32>().add(4).write(0);
            DEALLOCATED = 0;
            crate::util::video_engine::set_mock_instance(core::ptr::null_mut());
            assert_eq!(opaque_owned_record_destroy_with(record.cast(), record_dealloc), record.cast());
            assert_eq!(DEALLOCATED, 0);
        }
    }
}
