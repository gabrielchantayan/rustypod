//! Refresh the media player's collection cache.
//!
//! FUN_081114fc @ 0x081114fc: 136 bytes, next real entry 0x08111584.
//! Raw words establish ten outgoing plain BLs, zero predicated BLs, and
//! a final B to 0x08111664. Two incoming plain BLs (0x08114018,
//! 0x08114908), zero predicated callers. Cache backing +0xc08/+0xc0c at
//! player +0x3f8/+0x414; reset resource, configure (1,7), then cache four
//! collection queries at +0x3fc/+0x400/+0x404/+0x40c. Enable the inner
//! collection mode, cache its final query at +0x408, and reset again.
//! Deliberate deviations: reuse the existing Rust reset/configuration seams;
//! unported queries retain verified addresses, without claiming broader
//! identities. Host operations substitute retail dependencies. Express the
//! final tail branch as a call. Ghidra's extra arguments are not live inputs.

#[cfg(not(target_os = "none"))]
pub struct CollectionCacheOps {
    pub query: unsafe extern "C" fn(*mut u8, usize) -> u32,
    pub reset: unsafe extern "C" fn(*mut u32),
    pub configure: unsafe extern "C" fn(*mut u8, u32, u32),
    pub enable: unsafe extern "C" fn(*mut u8),
}

/// # Safety
/// Player must be aligned and writable through +0x4d6, with a valid u32
/// inner pointer at +0x30. All retail dependencies must be initialized;
/// callbacks must preserve subsequent pointer and field validity.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_refresh_collection_cache(
    player: *mut u32,
    #[cfg(not(target_os = "none"))] ops: &CollectionCacheOps,
) {
    for (field, address) in [(0x3f8, 0x0805_2034usize), (0x414, 0x0805_1fe4usize)] {
        let inner = player.add(0x30 / 4).read() as usize as *mut u8;
        #[cfg(target_os = "none")]
        let value = {
            let query: unsafe extern "C" fn(*mut u8) -> u32 = core::mem::transmute(address);
            query(inner)
        };
        #[cfg(not(target_os = "none"))]
        let value = (ops.query)(inner, address);
        player.add(field / 4).write(value);
    }
    #[cfg(target_os = "none")]
    super::media_player_reset_default_resource::media_player_reset_default_resource(player.cast());
    #[cfg(not(target_os = "none"))]
    (ops.reset)(player);
    let inner = player.add(0x30 / 4).read() as usize as *mut u8;
    #[cfg(target_os = "none")]
    super::media_player_reset_default_resource::firmware_configure_inner_state(inner, 1, 7);
    #[cfg(not(target_os = "none"))]
    (ops.configure)(inner, 1, 7);
    for (field, address) in [
        (0x3fc, 0x0805_3ea0usize), (0x400, 0x0805_3e50usize),
        (0x404, 0x0805_3f70usize), (0x40c, 0x0805_4140usize),
        (0x408, 0x0805_3f38usize),
    ] {
        if field == 0x408 {
            let inner = player.add(0x30 / 4).read() as usize as *mut u8;
            #[cfg(target_os = "none")]
            {
                let enable: unsafe extern "C" fn(*mut u8) -> u32 = core::mem::transmute(0x0806_64d0usize);
                let _ = enable(inner);
            }
            #[cfg(not(target_os = "none"))]
            (ops.enable)(inner);
        }
        let inner = player.add(0x30 / 4).read() as usize as *mut u8;
        #[cfg(target_os = "none")]
        let value = {
            let query: unsafe extern "C" fn(*mut u8) -> u32 = core::mem::transmute(address);
            query(inner)
        };
        #[cfg(not(target_os = "none"))]
        let value = (ops.query)(inner, address);
        player.add(field / 4).write(value);
    }
    #[cfg(target_os = "none")]
    super::media_player_reset_default_resource::media_player_reset_default_resource(player.cast());
    #[cfg(not(target_os = "none"))]
    (ops.reset)(player);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn query(inner: *mut u8, address: usize) -> u32 {
        match address {
            0x0805_2034 | 0x0805_1fe4 => {
                let backing = inner.add(0xf00).cast::<u32>().read() as usize as *const u32;
                backing.add(if address == 0x0805_2034 { 0xc08 / 4 } else { 0xc0c / 4 }).read()
            }
            _ => {
                let player = inner.cast::<u32>().read() as usize as *mut u32;
                let index = match address {
                    0x0805_3ea0 => 0, 0x0805_3e50 => 1, 0x0805_3f70 => 2,
                    0x0805_4140 => 3, 0x0805_3f38 => 4, _ => unreachable!(),
                };
                let fields = [0x3fc, 0x400, 0x404, 0x40c];
                // Later queries consume the cache written by earlier ones.
                let value = if index == 0 { inner.add(8).cast::<u32>().read() }
                    else { player.add(fields[index - 1] / 4).read().wrapping_add(1) };
                if index == 4 { assert_eq!(inner.add(0xef9).read(), 1); }
                value
            }
        }
    }
    unsafe extern "C" fn reset(player: *mut u32) {
        let inner = player.add(0x30 / 4).read() as usize as *mut u8;
        let replacement = inner.add(4).cast::<u32>().read();
        if replacement != 0 { player.add(0x30 / 4).write(replacement); }
        player.add(0x444 / 4).write(u32::MAX);
        player.cast::<u8>().add(0x4d6).write(0);
    }
    unsafe extern "C" fn configure(inner: *mut u8, first: u32, second: u32) {
        assert_eq!((first, second), (1, 7));
        let player = inner.cast::<u32>().read() as usize as *mut u32;
        player.add(0x444 / 4).write(42);
        player.cast::<u8>().add(0x4d6).write(1);
    }
    unsafe extern "C" fn enable(inner: *mut u8) { inner.add(0xef9).write(1); }

    #[test]
    fn preserves_full_width_values_order_and_reset_pointer_transition() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::MEDIA_PLAYER_COLLECTION_CACHE, 0x5000,
        ).expect("target-width collection cache fixture");
        let ops = CollectionCacheOps { query, reset, configure, enable };
        unsafe {
            for seed in [0, u32::MAX, 0x8000_0000] {
                slab.write_bytes(0xa5, 0x5000);
                let player = slab.cast::<u32>();
                let old = slab.add(0x1000);
                let new = slab.add(0x2000);
                let backing = slab.add(0x3000);
                player.add(0x30 / 4).write(old as usize as u32);
                old.add(4).cast::<u32>().write(new as usize as u32);
                old.add(0xf00).cast::<u32>().write(backing as usize as u32);
                backing.add(0xc08).cast::<u32>().write(seed);
                backing.add(0xc0c).cast::<u32>().write(!seed);
                new.cast::<u32>().write(player as usize as u32);
                new.add(4).cast::<u32>().write(0);
                new.add(8).cast::<u32>().write(seed);
                new.add(0xef9).write(0);
                media_player_refresh_collection_cache(player, &ops);
                assert_eq!(player.add(0x3f8 / 4).read(), seed);
                assert_eq!(player.add(0x414 / 4).read(), !seed);
                for (i, field) in [0x3fc, 0x400, 0x404, 0x40c, 0x408].into_iter().enumerate() {
                    assert_eq!(player.add(field / 4).read(), seed.wrapping_add(i as u32));
                }
                assert_eq!(player.add(0x30 / 4).read(), new as usize as u32);
                assert_eq!(player.add(0x444 / 4).read(), u32::MAX);
                assert_eq!(slab.add(0x4d6).read(), 0);
                assert_eq!(player.add(0x410 / 4).read(), 0xa5a5_a5a5);
                assert_eq!(slab.add(0x4d5).read(), 0xa5);
                assert_eq!(slab.add(0x4d7).read(), 0xa5);
            }
        }
    }
}
