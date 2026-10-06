//! Framework aligned-buffer state constructor @ 0x0816bfe4 (`FUN_0816bfe4`).
//!
//! True extent: 96 bytes [0x0816bfe4, 0x0816c044): 92 instruction
//! bytes and vtable literal 0x0898846c at 0x0816c040. The next real
//! function is the destructor at 0x0816c044. Whole-image word decoding
//! finds two incoming plain BLs (0x08149ca4, 0x08149d00), no predicated
//! BLs; two outgoing plain BLs to framework_sentinel_state_construct
//! (0x08275cd4) and aligned_buffer_init (0x081a81c4), no predicated BLs.
//!
//! Construct the sentinel prefix, install the derived vtable, construct
//! the aligned-buffer owner at +12, and clear the state at +20..+47
//! except padding +41..+43. Copy the aligned data address to +20 and,
//! only when nonzero, install the requested size at +24 (zero becomes
//! one). Return the object, not the embedded buffer. Callers replace
//! the vtable again and append a stream handle at +48. Other state-word
//! roles are not established. Deviations: none; fixed-width fields and
//! volatile accesses preserve target layout and store order on hosts.

use crate::cxx::framework_sentinel_state_construct::{
    framework_sentinel_state_construct, FrameworkSentinelState,
};
use crate::heap::aligned_buffer::aligned_buffer_init;

pub const FRAMEWORK_BUFFER_STATE_VTABLE: u32 = 0x0898_846c;

#[repr(C)]
pub struct FrameworkBufferState {
    pub base: FrameworkSentinelState,
    pub data: u32,
    pub allocation: u32,
    pub current_data: u32,
    pub capacity: u32,
    pub state_1c: u32,
    pub state_20: u32,
    pub state_24: u32,
    pub flag: u8,
    pub untouched_29_2b: [u8; 3],
    pub state_2c: u32,
}

/// # Safety
/// `storage` must be word-aligned writable storage for the complete object.
/// Its new allocation must later be released via `aligned_buffer_reset`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn framework_buffer_state_construct(
    storage: *mut FrameworkBufferState, size: u32,
) -> *mut FrameworkBufferState {
    let this = framework_sentinel_state_construct(storage.cast()).cast::<FrameworkBufferState>();
    core::ptr::addr_of_mut!((*this).base.base.vtable).write_volatile(FRAMEWORK_BUFFER_STATE_VTABLE);
    let buffer = aligned_buffer_init(core::ptr::addr_of_mut!((*this).data).cast(), size as usize);
    let this = buffer.sub(12).cast::<FrameworkBufferState>();
    core::ptr::addr_of_mut!((*this).current_data).write_volatile(0);
    core::ptr::addr_of_mut!((*this).capacity).write_volatile(0);
    core::ptr::addr_of_mut!((*this).state_1c).write_volatile(0);
    core::ptr::addr_of_mut!((*this).state_20).write_volatile(0);
    core::ptr::addr_of_mut!((*this).state_24).write_volatile(0);
    core::ptr::addr_of_mut!((*this).flag).write_volatile(0);
    core::ptr::addr_of_mut!((*this).state_2c).write_volatile(0);
    let data = core::ptr::addr_of!((*this).data).read_volatile();
    core::ptr::addr_of_mut!((*this).current_data).write_volatile(data);
    if data != 0 {
        core::ptr::addr_of_mut!((*this).capacity).write_volatile(if size == 0 { 1 } else { size });
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};

    #[test]
    fn constructor_preserves_padding_and_bounds_and_handles_empty_or_failed_buffers() {
        let _heap = mock_heap();
        assert_eq!(core::mem::size_of::<FrameworkBufferState>(), 48);
        for allocation in [0u32, 0xa110_0000, 0xa110_0001, 0xffff_ffff] {
            for size in [0u32, 1, 31, 32, 0x8000_0000, u32::MAX] {
                for fill in [0xa596_3cc7u32, u32::MAX] {
                    set_alloc_ret(allocation as usize as *mut u8);
                    let mut words = [fill; 14];
                    let mut expected = words;
                    let data = if allocation == 0 { 0 } else { allocation.wrapping_add(31) & !31 };
                    expected[1] = FRAMEWORK_BUFFER_STATE_VTABLE;
                    expected[2] = u32::MAX;
                    expected[3] &= 0xffff_ff00;
                    expected[4] = data;
                    expected[5] = allocation;
                    expected[6] = data;
                    expected[7] = if data == 0 { 0 } else { size.max(1) };
                    expected[8] = 0;
                    expected[9] = 0;
                    expected[10] = 0;
                    expected[11] &= 0xffff_ff00;
                    expected[12] = 0;
                    let storage = unsafe { words.as_mut_ptr().add(1).cast() };
                    assert_eq!(unsafe { framework_buffer_state_construct(storage, size) }, storage);
                    assert_eq!(words, expected, "allocation {allocation:#x}, size {size:#x}");
                }
            }
        }
    }
}
