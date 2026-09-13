//! TPodMediaPlayer pending-item append.
//!
//! `media_player_pending_item_append` — original: `FUN_0828a454` @
//! **0x0828a454**, **32 bytes** (`0x0828a454..0x0828a474`; the next distinct
//! function starts at `0x0828a474`). A complete decode of every ARM
//! B/BL-immediate word in `osos.dec` finds **6 direct inbound calls**:
//! unconditional `bl` at `0x081176b0`, `0x0828a5ec`, and `0x0828a630`; and
//! conditionally executed `blne` at `0x0828ac30`, `0x0828ac48`, and
//! `0x0828b0a4`. The three predicated sites show callers gate optional items;
//! this leaf itself has no NULL, item, or count-validity guard.
//!
//! # Algorithm
//!
//! Load the signed pending-item count at +0xe0. When it is less than 256,
//! increment it first and store the supplied target-width item word at
//! `this + 0xe4 + old_count * 4`; otherwise leave all memory untouched. The
//! signed comparison is deliberate: a corrupt negative count passes it, and
//! the ARM's wrapping indexed store is retained by using wrapping pointer
//! arithmetic. In particular, count `-1` increments to zero before the store
//! targets the count word itself.
//!
//! # Deliberate deviations
//!
//! None. The host model uses `u32` item words rather than host pointers, so its
//! +0xe0/+0xe4 layout exactly matches the 32-bit firmware layout.

/// Number of pending item words accepted by retailOS.
pub const MEDIA_PLAYER_PENDING_ITEM_CAPACITY: usize = 256;
const MEDIA_PLAYER_PENDING_ITEM_OFFSET: usize = 0xe4;

/// The portion of TPodMediaPlayer consumed by its pending-item worklist.
///
/// Item words are opaque target-width object handles. The caller later
/// dispatches through their vtables; this append leaf only copies the word.
#[repr(C)]
pub struct MediaPlayerPendingItems {
    /// +0x000..+0x0dc: player state not read or written by this leaf.
    pub state_before_pending_items: [u32; 0xe0 / 4],
    /// +0xe0: signed number of occupied pending-item slots.
    pub pending_item_count: i32,
    /// +0xe4..+0x4e4: target-width pending item words.
    pub pending_items: [u32; MEDIA_PLAYER_PENDING_ITEM_CAPACITY],
}

const _: [u8; 0xe0] = [0; core::mem::offset_of!(MediaPlayerPendingItems, pending_item_count)];
const _: [u8; MEDIA_PLAYER_PENDING_ITEM_OFFSET] =
    [0; core::mem::offset_of!(MediaPlayerPendingItems, pending_items)];
const _: [u8; 0x4e4] = [0; core::mem::size_of::<MediaPlayerPendingItems>()];

/// Appends an item word to the player's bounded pending-item worklist.
///
/// Original: `FUN_0828a454` @ 0x0828a454 (32 bytes; 6 direct callers: 3
/// unconditional `bl`, 3 `blne`, binary-verified in the module header).
///
/// # Safety
///
/// `player` must be non-NULL, aligned, and writable through its +0xe0 count
/// and the effective `+0xe4 + old_count * 4` store location whenever the
/// signed old count is below 256. The latter is deliberately not constrained
/// to the array for corrupt negative counts, matching the original's lack of
/// validation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.media_player_pending_item_append")]
pub unsafe extern "C" fn media_player_pending_item_append(
    player: *mut MediaPlayerPendingItems,
    item: u32,
) {
    let count = unsafe { (*player).pending_item_count };
    if count < MEDIA_PLAYER_PENDING_ITEM_CAPACITY as i32 {
        unsafe { (*player).pending_item_count = count.wrapping_add(1) };
        let slot = unsafe { core::ptr::addr_of_mut!((*player).pending_items) }
            .cast::<u32>()
            .wrapping_offset(count as isize);
        unsafe { slot.write(item) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn player_with_count(count: i32) -> MediaPlayerPendingItems {
        MediaPlayerPendingItems {
            state_before_pending_items: [0xcccc_cccc; 0xe0 / 4],
            pending_item_count: count,
            pending_items: [0xdead_beef; MEDIA_PLAYER_PENDING_ITEM_CAPACITY],
        }
    }

    #[test]
    fn appends_first_item_and_increments_count() {
        let mut player = player_with_count(0);

        unsafe { media_player_pending_item_append(&mut player, 0x1234_5678) };

        assert_eq!(player.pending_item_count, 1);
        assert_eq!(player.pending_items[0], 0x1234_5678);
        assert_eq!(player.pending_items[1], 0xdead_beef);
    }

    #[test]
    fn appends_last_available_item() {
        let mut player = player_with_count(255);

        unsafe { media_player_pending_item_append(&mut player, 0xa5a5_5a5a) };

        assert_eq!(player.pending_item_count, 256);
        assert_eq!(player.pending_items[255], 0xa5a5_5a5a);
    }

    #[test]
    fn full_worklist_leaves_memory_unchanged() {
        let mut player = player_with_count(256);
        let before = player.pending_items;

        unsafe { media_player_pending_item_append(&mut player, 0x1111_2222) };

        assert_eq!(player.pending_item_count, 256);
        assert_eq!(player.pending_items, before);
    }

    #[test]
    fn negative_count_can_overwrite_count_after_increment() {
        let mut player = player_with_count(-1);

        unsafe { media_player_pending_item_append(&mut player, 0xface_cafe) };

        assert_eq!(player.pending_item_count, 0xface_cafe_u32 as i32);
        assert!(player.pending_items.iter().all(|&item| item == 0xdead_beef));
    }
}
