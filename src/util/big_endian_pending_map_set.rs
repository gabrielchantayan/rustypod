//! Big-endian pending-map bit update.

/// `big_endian_pending_map_set` — original: `FUN_0836b6fc` @ `0x0836b6fc`
/// (**68 bytes exactly**, 17 ARM words from `stmdb sp!,{r3,r4,lr}` through
/// `ldmia sp!,{r3,r4,pc}`; the following literal at `0x0836b740` is
/// `0x39a00080`, and the next function begins at `0x0836b744`). Raw A32
/// decoding finds **one outbound plain `bl`, zero outbound predicated `bl`,
/// one inbound plain `bl` at `0x0804b3d0`, and one inbound predicated `blne`
/// at `0x080cb668**`.
///
/// Converts `group`'s low-five-bit position with
/// [`super::big_endian_word_bit_index::big_endian_word_bit_index`], then sets
/// or clears that bit in the pending-map word selected by `6 - (group >> 5)`.
/// The firmware returns zero. Deliberate deviations: the host substitutes a
/// test-installed pending-map base for the retail fixed address `0x39a00080`.
use super::big_endian_word_bit_index::big_endian_word_bit_index;

const PENDING_MAP_BASE: usize = 0x39a0_0080;

#[cfg(target_os = "none")]
#[inline(always)]
fn pending_map_base() -> *mut u32 {
    PENDING_MAP_BASE as *mut u32
}

#[cfg(not(target_os = "none"))]
static mut HOST_PENDING_MAP_BASE: *mut u32 = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pending_map_base() -> *mut u32 {
    unsafe { HOST_PENDING_MAP_BASE }
}

/// Updates the selected pending-map bit and returns zero.
///
/// # Safety
/// `group >> 5` must be at most six. On ARM the pending map at `0x39a00080`
/// must contain the selected aligned word; host callers must install an
/// equivalent base with [`install_host_pending_map`] before calling this.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.big_endian_pending_map_set")]
#[inline(never)]
pub unsafe extern "C" fn big_endian_pending_map_set(group: u32, pending: i32) -> u32 {
    let mut bit_index = 0;
    unsafe { big_endian_word_bit_index(group, &mut bit_index) };
    let map_word = unsafe { pending_map_base().add(6u32.wrapping_sub(group >> 5) as usize) };
    let mask = 1u32 << bit_index;
    let previous = unsafe { core::ptr::read_volatile(map_word) };
    let updated = if pending == 0 { previous & !mask } else { previous | mask };
    unsafe { core::ptr::write_volatile(map_word, updated) };
    0
}

/// Installs the host-only pending-map backing used by this port.
///
/// # Safety
/// `base` must remain valid for at least seven aligned `u32` words while any
/// host call to [`big_endian_pending_map_set`] can occur.
#[cfg(not(target_os = "none"))]
pub unsafe fn install_host_pending_map(base: *mut u32) {
    unsafe { HOST_PENDING_MAP_BASE = base };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{big_endian_pending_map_set, install_host_pending_map};
    use crate::testing::{hints, try_map_u32_slab, PENDING_MAP_SET_TEST_LOCK};

    #[test]
    fn updates_big_endian_bits_and_preserves_other_words() {
        let _lock = PENDING_MAP_SET_TEST_LOCK.lock();
        let Some(map) = try_map_u32_slab(hints::PENDING_MAP_SET, 7 * core::mem::size_of::<u32>()) else {
            return;
        };
        let map = map.cast::<u32>();
        unsafe {
            map.write_bytes(0, 7);
            *map.add(6) = 0x8000_0001;
            *map.add(5) = 0x8000_0000;
            install_host_pending_map(map);

            assert_eq!(big_endian_pending_map_set(0, 1), 0);
            assert_eq!(*map.add(6), 0x8100_0001);
            assert_eq!(*map.add(5), 0x8000_0000);

            assert_eq!(big_endian_pending_map_set(24, 0), 0);
            assert_eq!(*map.add(6), 0x8100_0000);

            assert_eq!(big_endian_pending_map_set(32, -7), 0);
            assert_eq!(*map.add(5), 0x8100_0000);
        }
    }
}
