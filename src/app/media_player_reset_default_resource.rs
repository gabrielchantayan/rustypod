//! Media-player default-resource reset.

use core::ptr;

const PLAYER_INNER_STATE: usize = 0x30;
const PLAYER_ACTIVE_INDEX: usize = 0x444;
const PLAYER_PENDING: usize = 0x4d6;

/// ABI seam for `FUN_08066618`, whose concrete operation name is not yet
/// established. It stores the two supplied selector bytes into the inner
/// object's configuration words.
type ConfigureInnerState = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_configure_inner_state(
    inner_state: *mut u8,
    first_selector: u32,
    second_selector: u32,
) {
    let call: ConfigureInnerState = core::mem::transmute(0x0806_6618usize);
    call(inner_state, first_selector, second_selector);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_configure_inner_state(_: *mut u8, _: u32, _: u32) {
    panic!("media_player_reset_default_resource requires 0x08066618")
}

#[cfg(target_os = "none")]
const DEFAULT_CONFIGURE_INNER_STATE: ConfigureInnerState = firmware_configure_inner_state;
#[cfg(not(target_os = "none"))]
const DEFAULT_CONFIGURE_INNER_STATE: ConfigureInnerState = missing_configure_inner_state;

static mut CONFIGURE_INNER_STATE: ConfigureInnerState = DEFAULT_CONFIGURE_INNER_STATE;

/// media_player_reset_default_resource — original: `FUN_08111664` @
/// `0x08111664` (56 bytes; next real function starts at `0x0811169c`).
///
/// Raw A32 decoding finds three inbound plain unconditional `bl` sites
/// (`0x08111528`, `0x08111834`, `0x08230144`) and no predicated callers. The
/// body has two direct unconditional `bl` instructions: the ported
/// [`crate::util::inner_state::object_select_resource_index`] at `0x0806673c`
/// and unported `0x08066618`.
///
/// Selects resource zero in the player's inner state, configures its two
/// selector slots to `(1, 3)`, invalidates the player's active index, and
/// clears its pending byte. Deliberate deviation: the unported second callee
/// is an ABI-shaped volatile operation slot on host and a direct firmware call
/// on target; its concrete semantic identity is not inferred from its address.
///
/// # Safety
///
/// `player` must point to writable fields through `+0x4d6` and contain a
/// valid inner-state pointer at `+0x30` for both invoked operations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_reset_default_resource(player: *mut u8) {
    let inner_state = (player.add(PLAYER_INNER_STATE) as *const u32).read() as usize as *mut u8;
    let _ = crate::util::inner_state::object_select_resource_index(inner_state, 0);
    let configure = ptr::read_volatile(ptr::addr_of!(CONFIGURE_INNER_STATE));
    configure(inner_state, 1, 3);
    (player.add(PLAYER_ACTIVE_INDEX) as *mut u32).write_volatile(u32::MAX);
    player.add(PLAYER_PENDING).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CONFIGURE_CALL: (*mut u8, u32, u32) = (core::ptr::null_mut(), 0, 0);

    unsafe extern "C" fn record_configuration(inner_state: *mut u8, first: u32, second: u32) {
        CONFIGURE_CALL = (inner_state, first, second);
    }

    struct ConfigurationRestore;

    impl Drop for ConfigurationRestore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(CONFIGURE_INNER_STATE).write_volatile(DEFAULT_CONFIGURE_INNER_STATE);
            }
        }
    }

    #[test]
    fn resets_player_fields_after_default_selection_and_configuration() {
        use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

        let _guard = TEST_LOCK.lock();
        let Some(player) = try_map_u32_slab(hints::MEDIA_PLAYER_RESET_DEFAULT_RESOURCE, 0x3000) else {
            assert!(note_missing_u32_fixture("app/media_player_reset_default_resource"));
            return;
        };
        let _restore = ConfigurationRestore;
        unsafe {
            core::ptr::write_bytes(player, 0, 0x3000);
            let inner_state = player.add(0x1000);
            // Kind 1 with zero resources makes the already-ported selector
            // reject index zero before it reaches its host-only cleanup seams.
            inner_state.write(1);
            inner_state.add(0xf68).cast::<u32>().write(0);
            player.add(PLAYER_INNER_STATE).cast::<u32>().write(inner_state as usize as u32);
            player.add(PLAYER_ACTIVE_INDEX).cast::<u32>().write(9);
            player.add(PLAYER_PENDING).write(1);
            CONFIGURE_CALL = (core::ptr::null_mut(), 0, 0);
            ptr::addr_of_mut!(CONFIGURE_INNER_STATE).write_volatile(record_configuration);

            media_player_reset_default_resource(player);

            assert_eq!(CONFIGURE_CALL, (inner_state, 1, 3));
            assert_eq!(player.add(PLAYER_ACTIVE_INDEX).cast::<u32>().read(), u32::MAX);
            assert_eq!(player.add(PLAYER_PENDING).read(), 0);
        }
    }
}
