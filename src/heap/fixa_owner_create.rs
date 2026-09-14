//! FixA owner construction.
//!
//! `fixa_owner_create` — retailOS `FUN_0805df24` @ `0x0805df24` (92 bytes of
//! instructions plus its 4-byte literal pool at `0x0805df80`; next function
//! starts at `0x0805df84`). A complete ARM B/BL decode of `osos.dec` finds six
//! inbound `bl` calls, all unconditional, at `0x0805ddac`, `0x0805e1f0`,
//! `0x0805e208`, `0x0805e2c4`, `0x080cb204`, and `0x080d2700`; there are no
//! predicated `bl` calls. One additional `beq` tail branch at `0x080d2718`
//! reaches this entry after a successful first allocation.
//!
//! Allocates the 16-byte zerofilled FixA owner through `calloc_tag4`, writes
//! the `FixA` magic word, rounds a minimum-four-byte requested capacity up to
//! a 16-byte boundary, and records the caller's payload word. It stores the
//! allocation result to the target-width output word before testing for OOM;
//! on NULL it returns `-108` (`0xffffff94`). The fourth word remains zero from
//! the zerofill allocation and is the empty FixL-list head consumed by
//! `fixa_owner_destroy`.
//!
//! Deliberate deviation: the target's direct `bl 0x0805d1dc` is the existing
//! `calloc_tag4` Rust port, whose dispatch reaches the heap through `HEAP_OPS`
//! on host builds. `FixA` describes only the verified literal `0x46697841`.

use crate::heap::fixa::FixaOwner;
use crate::heap::veneers::calloc_tag4;

const FIXA_MAGIC: u32 = 0x4669_7841;
const FIXA_OWNER_SIZE: usize = 0x10;
const ALLOCATION_FAILURE: i32 = -108;

const _: () = assert!(core::mem::size_of::<FixaOwner>() == FIXA_OWNER_SIZE);

/// Creates a zerofilled FixA owner and writes its target-width address.
///
/// # Safety
///
/// `out_owner` must designate a writable 32-bit target word. On success the
/// returned address names a tag-4 allocation with the `FixaOwner` layout; on
/// failure this function writes zero and does not dereference that allocation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fixa_owner_create")]
#[inline(never)]
pub unsafe extern "C" fn fixa_owner_create(
    requested_capacity: u32,
    payload: u32,
    out_owner: *mut u32,
) -> i32 {
    unsafe {
        let owner = calloc_tag4(FIXA_OWNER_SIZE).cast::<FixaOwner>();
        out_owner.write(owner as usize as u32);
        if owner.is_null() {
            return ALLOCATION_FAILURE;
        }

        (*owner).magic = FIXA_MAGIC;
        (*owner).allocation_size = requested_capacity.max(4).wrapping_add(15) & !0x0f;
        (*owner).payload = payload;
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_zero_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{self, addr_of};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x100;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::FIXA_OWNER_CREATE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    #[test]
    fn creates_a_tag4_zerofilled_owner_with_minimum_and_rounded_capacity() {
        let _test_guard = TEST_LOCK.lock();
        let _heap_guard = mock_heap();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("heap/fixa_owner_create"));
            return;
        };
        let base = base as *mut u8;
        let out_owner = unsafe { base.add(0x10).cast::<u32>() };
        let owner = unsafe { base.add(0x40).cast::<FixaOwner>() };
        let requests = [0, 1, 3, 4, 5, 16, 17, u32::MAX];

        unsafe {
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            set_alloc_ret(owner.cast());
            for requested_capacity in requests {
                out_owner.write(0xdead_beef);
                assert_eq!(fixa_owner_create(requested_capacity, 0x1357_9bdf, out_owner), 0);
                assert_eq!(out_owner.read(), owner as usize as u32);
                assert_eq!(addr_of!((*owner).magic).read(), FIXA_MAGIC);
                assert_eq!(
                    addr_of!((*owner).allocation_size).read(),
                    requested_capacity.max(4).wrapping_add(15) & !0x0f
                );
                assert_eq!(addr_of!((*owner).payload).read(), 0x1357_9bdf);
                assert_eq!(addr_of!((*owner).first_fixl).read(), 0);
            }
            assert_eq!(alloc_zero_log(), (requests.len(), FIXA_OWNER_SIZE, 4));
        }
    }

    #[test]
    fn allocation_failure_stores_null_before_returning_the_retail_error() {
        let _test_guard = TEST_LOCK.lock();
        let _heap_guard = mock_heap();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("heap/fixa_owner_create"));
            return;
        };
        let base = base as *mut u8;
        let out_owner = unsafe { base.add(0x10).cast::<u32>() };
        let owner = unsafe { base.add(0x40).cast::<FixaOwner>() };

        unsafe {
            ptr::write_bytes(base, 0xa5, FIXTURE_LEN);
            out_owner.write(0xdead_beef);
            set_alloc_ret(core::ptr::null_mut());

            assert_eq!(fixa_owner_create(0x20, 7, out_owner), ALLOCATION_FAILURE);
            assert_eq!(out_owner.read(), 0, "the raw routine stores r0 before its NULL test");
            assert_eq!(addr_of!((*owner).magic).read(), 0xa5a5_a5a5);
            assert_eq!(alloc_zero_log(), (1, FIXA_OWNER_SIZE, 4));
        }
    }
}
