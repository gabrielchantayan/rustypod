//! Refresh the media player's cached inner-state values.
//!
//! FUN_081117e4 @ 0x081117e4: 132 bytes, next real boundary 0x08111868.
//! Raw A32 words verify seven plain outbound BLs, zero predicated BLs,
//! and a final B to 0x08111664. Two plain inbound BLs at 0x08114010 and
//! 0x08114900; no predicated callers. Cache inner backing words +0xc04,
//! +0xbfc, +0xc00, +0xc10 in player +0x418,+0x420,+0x41c,+0x428;
//! store their wrapping sum at +0x424. Reset default resource, configure
//! selectors (2,7), cache the global inner-state +0xf70 value at +0x410,
//! then reset default resource again. The values' broader meanings are unknown.
//! Deliberate deviations: reuse the Rust reset port; verified unported getters
//! retain address-based ABI calls on target, host-only operations model them.
//! The final tail branch is expressed as an ordinary call.

#[cfg(not(target_os = "none"))]
pub struct CachedValuesRefreshOps {
    pub read_backing_word: unsafe extern "C" fn(*mut u8, usize) -> u32,
    pub reset: unsafe extern "C" fn(*mut u32),
    pub configure: unsafe extern "C" fn(*mut u8, u32, u32),
    pub read_global_word: unsafe extern "C" fn() -> u32,
}

/// # Safety
/// Player must be aligned and writable through +0x4d6, with a valid target-width
/// inner pointer at +0x30. Its backing pointer at +0xf00 must be readable through
/// +0xc10. Firmware global state and reset/configuration dependencies must be
/// initialized. Host operations must preserve the validity of subsequent reads.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_refresh_cached_values(
    player: *mut u32,
    #[cfg(not(target_os = "none"))] ops: &CachedValuesRefreshOps,
) {
    for (field, backing_offset, address) in [
        (0x418, 0xc04, 0x0805_200cusize),
        (0x420, 0xbfc, 0x0805_1ff0usize),
        (0x41c, 0xc00, 0x0805_2040usize),
        (0x428, 0xc10, 0x0805_2028usize),
    ] {
        let inner = player.add(0x30 / 4).read() as usize as *mut u8;
        #[cfg(target_os = "none")]
        let value = {
            let _ = backing_offset;
            let read: unsafe extern "C" fn(*mut u8) -> u32 = core::mem::transmute(address);
            read(inner)
        };
        #[cfg(not(target_os = "none"))]
        let value = {
            let _ = address;
            (ops.read_backing_word)(inner, backing_offset)
        };
        player.add(field / 4).write(value);
    }
    let total = player.add(0x418 / 4).read()
        .wrapping_add(player.add(0x420 / 4).read())
        .wrapping_add(player.add(0x41c / 4).read())
        .wrapping_add(player.add(0x428 / 4).read());
    player.add(0x424 / 4).write(total);
    #[cfg(target_os = "none")]
    super::media_player_reset_default_resource::media_player_reset_default_resource(player.cast());
    #[cfg(not(target_os = "none"))]
    (ops.reset)(player);
    let inner = player.add(0x30 / 4).read() as usize as *mut u8;
    #[cfg(target_os = "none")]
    super::media_player_reset_default_resource::firmware_configure_inner_state(inner, 2, 7);
    #[cfg(not(target_os = "none"))]
    (ops.configure)(inner, 2, 7);
    #[cfg(target_os = "none")]
    let global_value = {
        let read: unsafe extern "C" fn() -> u32 = core::mem::transmute(0x0805_42b4usize);
        read()
    };
    #[cfg(not(target_os = "none"))]
    let global_value = (ops.read_global_word)();
    player.add(0x410 / 4).write(global_value);
    #[cfg(target_os = "none")]
    super::media_player_reset_default_resource::media_player_reset_default_resource(player.cast());
    #[cfg(not(target_os = "none"))]
    (ops.reset)(player);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn read_backing(inner: *mut u8, offset: usize) -> u32 {
        let backing = inner.add(0xf00).cast::<u32>().read() as usize as *const u8;
        backing.add(offset).cast::<u32>().read()
    }
    unsafe extern "C" fn reset(player: *mut u32) {
        // First reset replaces the inner pointer, making the reload observable.
        let inner = player.add(0x30 / 4).read() as usize as *mut u8;
        let replacement = inner.cast::<u32>().read();
        if replacement != 0 && replacement != player as usize as u32 {
            player.add(0x30 / 4).write(replacement);
        }
        player.add(0x444 / 4).write(u32::MAX);
        player.cast::<u8>().add(0x4d6).write(0);
    }
    unsafe extern "C" fn configure(inner: *mut u8, first: u32, second: u32) {
        inner.add(0xe30).cast::<u32>().write(first);
        inner.add(0xe34).cast::<u32>().write(second);
        // Model a configuration side effect on the owning player's reset fields.
        let player = inner.cast::<u32>().read() as usize as *mut u32;
        player.add(0x444 / 4).write(23);
        player.cast::<u8>().add(0x4d6).write(1);
    }
    unsafe extern "C" fn global_word() -> u32 { 0x8000_1234 }

    #[test]
    fn caches_zero_and_wrapping_values_and_reloads_after_reset() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::MEDIA_PLAYER_CACHED_VALUES, 0x5000,
        ).expect("target-width cached-value fixture");
        let ops = CachedValuesRefreshOps {
            read_backing_word: read_backing, reset, configure, read_global_word: global_word,
        };
        unsafe {
            for values in [[0, 0, 0, 0], [u32::MAX, 2, 0x8000_0000, 0x8000_0003]] {
                slab.write_bytes(0, 0x5000);
                let player = slab.cast::<u32>();
                let old = slab.add(0x1000);
                let new = slab.add(0x2000);
                let backing = slab.add(0x3000);
                player.add(0x30 / 4).write(old as usize as u32);
                old.cast::<u32>().write(new as usize as u32);
                old.add(0xf00).cast::<u32>().write(backing as usize as u32);
                new.cast::<u32>().write(player as usize as u32);
                for (offset, value) in [0xc04, 0xbfc, 0xc00, 0xc10].into_iter().zip(values) {
                    backing.add(offset).cast::<u32>().write(value);
                }
                player.add(0x444 / 4).write(17);
                slab.add(0x4d6).write(1);
                media_player_refresh_cached_values(player, &ops);
                for (offset, value) in [0x418, 0x420, 0x41c, 0x428].into_iter().zip(values) {
                    assert_eq!(player.add(offset / 4).read(), value);
                }
                assert_eq!(player.add(0x424 / 4).read(), values.into_iter().fold(0u32, u32::wrapping_add));
                assert_eq!(player.add(0x410 / 4).read(), 0x8000_1234);
                assert_eq!(old.add(0xe30).cast::<u32>().read(), 0);
                assert_eq!(new.add(0xe30).cast::<u32>().read(), 2);
                assert_eq!(new.add(0xe34).cast::<u32>().read(), 7);
                assert_eq!(player.add(0x444 / 4).read(), u32::MAX);
                assert_eq!(slab.add(0x4d6).read(), 0);
            }
        }
    }
}
