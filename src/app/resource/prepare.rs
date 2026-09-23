//! Resource-arena preparation before teardown.

use core::ptr;

const PREPARE_GUARD_ADDRESS: usize = 0x089c_c640;
const PREPARE_FINISH_ADDRESS: usize = 0x0818_3f04;

/// resource_arena_prepare — original: `FUN_081818b4` @ **0x081818b4**
/// (148 bytes exactly, `0x081818b4..0x08181948`; the next function starts at
/// `0x0818194c`). Raw ARM has three plain unconditional `bl` calls and no
/// predicated `bl` calls.
///
/// Raises the `0x089cc640` reentrancy byte, removes each identifier in the
/// ARM-word range `state+0x58..state+0x5c` from the lazy element registry,
/// empties that range, lowers the byte, then tail-dispatches to
/// `FUN_08183f04(state, state+0x70)`. The final dispatch is a verified
/// firmware boundary; its semantic identity is deliberately not invented.
///
/// Deliberate deviation: Rust makes the final call normally rather than
/// preserving ARM's tail branch.
///
/// # Safety
///
/// `state` must be writable and hold valid, naturally aligned ARM-word
/// pointers at `+0x58` and `+0x5c`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_arena_prepare")]
#[inline(never)]
pub unsafe extern "C" fn resource_arena_prepare(state: *mut u8) {
    #[cfg(target_os = "none")]
    let guard = PREPARE_GUARD_ADDRESS as *mut u8;
    #[cfg(not(target_os = "none"))]
    let guard = ptr::addr_of_mut!(HOST_PREPARE_GUARD);

    ptr::write_volatile(guard, 1);
    let begin = ptr::read((state.add(0x58)).cast::<u32>()) as usize as *mut u32;
    let end = ptr::read((state.add(0x5c)).cast::<u32>()) as usize as *mut u32;
    let mut id = begin;
    while id != end {
        #[cfg(target_os = "none")]
        crate::app::element_registry::element_registry_remove_for_id(
            crate::app::singletons::lazy_singleton_0x3c().cast(),
            ptr::read(id),
        );
        id = id.add(1);
    }
    ptr::write(state.add(0x5c).cast::<u32>(), begin as usize as u32);
    ptr::write_volatile(guard, 0);

    #[cfg(target_os = "none")]
    {
        let finish: unsafe extern "C" fn(*mut u8, *mut u8) = core::mem::transmute(PREPARE_FINISH_ADDRESS);
        finish(state, ptr::read(state.add(0x70).cast::<u32>()) as usize as *mut u8);
    }
}

#[cfg(not(target_os = "none"))]
static mut HOST_PREPARE_GUARD: u8 = 0;

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn drains_a_nonempty_target_word_range() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::RESOURCE_ARENA_PREPARE,
            0x1000,
        ) else { return };
        unsafe {
            let state = slab;
            let ids = slab.add(0x200).cast::<u32>();
            *ids = 0x11;
            *ids.add(1) = 0x22;
            ptr::write(state.add(0x58).cast::<u32>(), ids as usize as u32);
            ptr::write(state.add(0x5c).cast::<u32>(), ids.add(2) as usize as u32);
            resource_arena_prepare(state);
            assert_eq!(ptr::read(state.add(0x5c).cast::<u32>()), ids as usize as u32);
            assert_eq!(ptr::read_volatile(ptr::addr_of!(HOST_PREPARE_GUARD)), 0);
        }
    }
}
