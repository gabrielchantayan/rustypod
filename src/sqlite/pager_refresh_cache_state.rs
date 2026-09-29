//! Refreshes a pager's cached list state — `FUN_082d8e74` @ `0x082d8e74`.
//!
//! Raw `osos.dec` establishes the true 60-byte extent
//! `0x082d8e74..0x082d8eaf`; the word at `0x082d8eb0` is the literal
//! `0x08adc2c0`, and `0x082d8eb4` begins the next independently linked
//! function. Whole-image A32 decoding finds two inbound plain `bl` calls
//! (`0x082ddc1c` and `0x08392afc`) and no inbound predicated `bl` calls. The
//! body contains no `bl` instructions.
//!
//! Algorithm: copy pager `+0x7c` to `+0x84`. Unless pager `+0x14` is set,
//! walk the global list at `0x08adc2c0` through node `+0x2c` links until its
//! first node whose `+0x1e` byte is clear, then store that node at global
//! `+0x08`.
//!
//! Deliberate deviation: target code uses the verified fixed global address;
//! host tests supply an equivalent target-width state block.

const PAGER_LIST: usize = 0x7c;
const PAGER_CACHED_LIST: usize = 0x84;
const PAGER_HAS_PRIVATE_LIST: usize = 0x14;
const ALLOCATOR_STATE: usize = 0x08ad_c2c0;
const STATE_CACHED_NODE: usize = 0x08;
const NODE_ACTIVE: usize = 0x1e;
const NODE_NEXT: usize = 0x2c;

#[inline(always)]
unsafe fn refresh_with(pager: *mut u8, allocator_state: *mut u8) {
    pager.add(PAGER_CACHED_LIST).cast::<u32>().write(pager.add(PAGER_LIST).cast::<u32>().read());
    if pager.add(PAGER_HAS_PRIVATE_LIST).read() != 0 {
        return;
    }

    let mut node = allocator_state.cast::<u32>().read() as usize as *mut u8;
    while !node.is_null() && node.add(NODE_ACTIVE).read() != 0 {
        node = node.add(NODE_NEXT).cast::<u32>().read() as usize as *mut u8;
    }
    allocator_state.add(STATE_CACHED_NODE).cast::<u32>().write(node as usize as u32);
}

/// Refreshes the pager's cached list state and the allocator's cached node.
///
/// # Safety
/// `pager` must be a writable target-layout pager. Its list nodes and the
/// fixed allocator state must remain valid while this function walks them.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_refresh_cache_state")]
#[inline(never)]
pub unsafe extern "C" fn pager_refresh_cache_state(pager: *mut u8) {
    refresh_with(pager, ALLOCATOR_STATE as *mut u8);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const PAGER: usize = 0x000;
    const STATE: usize = 0x100;
    const FIRST_NODE: usize = 0x200;
    const SECOND_NODE: usize = 0x300;

    fn fixture() -> Option<*mut u8> {
        try_map_u32_slab(hints::SQLITE_PAGER_REFRESH_CACHE_STATE, SLAB_LEN)
    }

    #[test]
    fn copies_list_and_caches_first_inactive_global_node() {
        let Some(slab) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/pager_refresh_cache_state"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let pager = slab.add(PAGER);
            let state = slab.add(STATE);
            let first = slab.add(FIRST_NODE);
            let second = slab.add(SECOND_NODE);
            pager.add(PAGER_LIST).cast::<u32>().write(0x1234_5678);
            state.cast::<u32>().write(first as usize as u32);
            first.add(NODE_ACTIVE).write(1);
            first.add(NODE_NEXT).cast::<u32>().write(second as usize as u32);
            refresh_with(pager, state);
            assert_eq!(pager.add(PAGER_CACHED_LIST).cast::<u32>().read(), 0x1234_5678);
            assert_eq!(state.add(STATE_CACHED_NODE).cast::<u32>().read(), second as usize as u32);
        }
    }

    #[test]
    fn preserves_global_cache_for_private_pager() {
        let Some(slab) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/pager_refresh_cache_state"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let pager = slab.add(PAGER);
            let state = slab.add(STATE);
            pager.add(PAGER_LIST).cast::<u32>().write(0x8765_4321);
            pager.add(PAGER_HAS_PRIVATE_LIST).write(1);
            state.add(STATE_CACHED_NODE).cast::<u32>().write(0xfeed_beef);
            refresh_with(pager, state);
            assert_eq!(pager.add(PAGER_CACHED_LIST).cast::<u32>().read(), 0x8765_4321);
            assert_eq!(state.add(STATE_CACHED_NODE).cast::<u32>().read(), 0xfeed_beef);
        }
    }

    #[test]
    fn caches_null_for_an_empty_global_list() {
        let Some(slab) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/pager_refresh_cache_state"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let state = slab.add(STATE);
            state.add(STATE_CACHED_NODE).cast::<u32>().write(0xffff_ffff);
            refresh_with(slab.add(PAGER), state);
            assert_eq!(state.add(STATE_CACHED_NODE).cast::<u32>().read(), 0);
        }
    }
}
