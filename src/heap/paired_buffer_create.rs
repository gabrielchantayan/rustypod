//! Pooled paired-buffer construction.
//!
//! `FUN_0805dd8c` @ 0x0805dd8c: true extent 144 bytes, comprising 120
//! instruction bytes and 24 literal bytes; next function starts at 0x0805de1c.
//! Raw word decoding verifies two incoming plain BLs, zero predicated BLs;
//! three outgoing plain BLs, zero predicated BLs. Lazily create a FixA owner
//! with 0x1e9c-byte buffers and three slots, register key 0x080d9448, acquire
//! a buffer, and set capacities at +4 and +0x1464 to 0x1460 and 0xa3c.
//! Creation/registration failure returns NULL without rolling back the owner;
//! subsequent calls skip registration once the owner exists.
//! Deviations: existing Rust ports replace owner creation and registration;
//! FIXED_POOL_OPS dispatches the unported allocator. Host state is supplied
//! explicitly; all object offsets and cached addresses remain 32-bit words.
//! Codegen uses an indirect BLX for the existing allocator seam and reverses
//! the two independent capacity stores; neither field is volatile.

use core::ptr;
use super::fixa_owner_create::fixa_owner_create;
use crate::util::word_record_register::word_record_register;
use crate::ui::pool_entry_create::FIXED_POOL_OPS;

#[cfg(not(target_os = "none"))]
pub static mut PAIRED_BUFFER_OWNER_SLOT: *mut u32 = ptr::null_mut();

/// Allocate the paired buffer used by the two-sided caller at 0x0806cc54.
///
/// # Safety
/// Externally serialize the firmware pool and record table. Host callers must
/// supply a writable owner slot and record table. The allocator must return
/// NULL or an aligned writable buffer of at least 0x1e9c bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn paired_buffer_create() -> *mut u32 {
    #[cfg(target_os = "none")]
    let slot = 0x089c_b194 as *mut u32;
    #[cfg(not(target_os = "none"))]
    let slot = ptr::read_volatile(ptr::addr_of!(PAIRED_BUFFER_OWNER_SLOT));
    if ptr::read_volatile(slot) == 0 {
        if fixa_owner_create(0x1e9c, 3, slot) != 0 { return ptr::null_mut(); }
        if word_record_register(0x080d_9448, 0, 0, 0, ptr::null_mut()) != 0 {
            return ptr::null_mut();
        }
    }
    let ops = ptr::read_volatile(ptr::addr_of!(FIXED_POOL_OPS));
    let buffer = (ops.acquire)(ptr::read_volatile(slot) as usize as *mut u8).cast::<u32>();
    if !buffer.is_null() {
        buffer.add(1).write(0x1460);
        buffer.add(0x1464 / 4).write(0xa3c);
    }
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, alloc_zero_log};
    use crate::testing::{hints, try_map_u32_slab};
    use crate::ui::pool_entry_create::FixedPoolOps;
    use crate::util::word_record_register::WORD_RECORD_TABLE;

    static mut RESULT: *mut u8 = ptr::null_mut();
    unsafe extern "C" fn acquire(owner: *mut u8) -> *mut u8 {
        let words = owner.cast::<u32>();
        assert_eq!(words.read(), 0x4669_7841);
        assert_eq!(words.add(1).read(), 0x1ea0);
        assert_eq!(words.add(2).read(), 3);
        RESULT
    }
    struct Restore(*mut u32, *mut u32, FixedPoolOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            PAIRED_BUFFER_OWNER_SLOT = self.0;
            WORD_RECORD_TABLE = self.1;
            FIXED_POOL_OPS = self.2;
        } }
    }

    #[test]
    fn allocation_failure_retry_cached_owner_and_buffer_boundaries() {
        let _pool = crate::testing::UI_POOL_ENTRY_CREATE_TEST_LOCK.lock().unwrap();
        let _heap = mock_heap();
        let base = try_map_u32_slab(hints::PAIRED_BUFFER_CREATE, 0x3000)
            .expect("low-address paired-buffer fixture");
        unsafe {
            let _restore = Restore(PAIRED_BUFFER_OWNER_SLOT, WORD_RECORD_TABLE, FIXED_POOL_OPS);
            ptr::write_bytes(base, 0, 0x3000);
            PAIRED_BUFFER_OWNER_SLOT = base.cast();
            WORD_RECORD_TABLE = base.add(0x100).cast();
            FIXED_POOL_OPS = FixedPoolOps { acquire };
            set_alloc_ret(ptr::null_mut());
            assert!(paired_buffer_create().is_null());
            assert_eq!(base.cast::<u32>().read(), 0);
            assert_eq!(WORD_RECORD_TABLE.read(), 0);
            set_alloc_ret(base.add(0x40));
            RESULT = ptr::null_mut();
            assert!(paired_buffer_create().is_null());
            assert_eq!(base.cast::<u32>().read(), base.add(0x40) as usize as u32);
            assert_eq!(core::slice::from_raw_parts(WORD_RECORD_TABLE, 8),
                &[0x080d_9448, 0, 0, 0, 0, 0, 0, 0]);
            RESULT = base.add(0x1000);
            ptr::write_bytes(RESULT, 0xa5, 0x1e9c);
            let buffer = paired_buffer_create();
            assert_eq!(buffer, RESULT.cast());
            let words = core::slice::from_raw_parts(buffer, 0x1e9c / 4);
            for (i, &word) in words.iter().enumerate() {
                assert_eq!(word, match i { 1 => 0x1460, 0x519 => 0xa3c, _ => 0xa5a5_a5a5 });
            }
            assert_eq!(WORD_RECORD_TABLE.add(4).read(), 0, "cached owner must not register again");
            assert_eq!(alloc_zero_log(), (2, 16, 4));
        }
    }
}
