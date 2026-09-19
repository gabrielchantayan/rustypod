//! Cache address translation.
//!
//! Port:
//! - [`cache_address_translate`] — original: `FUN_08090780` @ `0x08090780`
//!   (32 bytes; the independently linked next function starts at `0x080907a4`).

const CACHE_ADDRESS_MAP_ADDRESS: usize = 0x08a1_0718;
const CACHE_SEGMENT: u32 = 0x180;

#[cfg(not(target_os = "none"))]
static HOST_CACHE_ADDRESS_MAP: [u32; 3] = [0, 0x1800_0000, 0x2200_0000];

#[inline(always)]
unsafe fn cache_address_map() -> *const u32 {
    #[cfg(target_os = "none")]
    {
        core::ptr::read_volatile(CACHE_ADDRESS_MAP_ADDRESS as *const *const u32)
    }
    #[cfg(not(target_os = "none"))]
    {
        HOST_CACHE_ADDRESS_MAP.as_ptr()
    }
}

/// cache_address_translate — original: `FUN_08090780` @ `0x08090780`
/// (32 bytes, `0x08090780..0x080907a0`; `0x080907a0` is its literal-pool
/// word and `0x080907a4` starts the next real function).
///
/// Verified call count: zero direct `bl` instructions, plain or predicated.
/// Whole-image A32 branch decoding finds four inbound plain `bl` calls
/// (`0x081bc04c`, `0x081ef010`, `0x081ef0c8`, `0x08296a14`) and zero inbound
/// predicated `bl` calls.
///
/// Translates an address in the `0x180` MiB segment from the runtime cache
/// map's source base (`+4`) to its mapped base (`+8`), preserving its offset
/// with ARM `u32` wrapping. Other address segments pass through unchanged.
///
/// Deliberate deviation: host builds use the observed `0x1800_0000` to
/// `0x2200_0000` cache-map values because the target's map-pointer word at
/// `0x08a10718` is initialized at runtime and is not host-mapped.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_address_translate(address: u32) -> u32 {
    if address >> 20 != CACHE_SEGMENT {
        return address;
    }

    let map = cache_address_map();
    address
        .wrapping_sub(core::ptr::read_volatile(map.add(1)))
        .wrapping_add(core::ptr::read_volatile(map.add(2)))
}

#[cfg(test)]
mod tests {
    use super::cache_address_translate;

    #[test]
    fn maps_every_offset_in_the_cache_segment() {
        for address in [0x1800_0000, 0x1800_0001, 0x180f_ffff] {
            assert_eq!(unsafe { cache_address_translate(address) }, address + 0x0a00_0000);
        }
    }

    #[test]
    fn preserves_adjacent_and_unrelated_segments() {
        for address in [0, 0x17ff_ffff, 0x1810_0000, 0xffff_ffff] {
            assert_eq!(unsafe { cache_address_translate(address) }, address);
        }
    }
}
