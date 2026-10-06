//! `media_player_trim_current_item` — `FUN_0817a800` @ **0x0817a800**.
//! True extent: **212 bytes**, ending at 0x0817a8d4's next-function push.
//! Whole-image A32 BL decoding: two unconditional inbound calls (0x0817bcac,
//! 0x0817d290), zero predicated inbound calls; seven unconditional outbound
//! BLs, zero predicated outbound BLs, and four register BLX sites.
//!
//! If the class-0x9400 current item matches the player and the unsigned player
//! index reaches the class limit, release the embedded queue member, re-read
//! the index, and perform wrapping(index - limit + 1) removals. Each removal
//! invokes player slot +0x130 with zero then the class operation with zero.
//! Copy the final index into optional source+0x1c and refresh the queue, even
//! when the wrapping removal count is zero. Return whether a removal ran.
//!
//! Deliberate deviations: reuse the four existing Rust dependencies; preserve
//! the two unported class operations as fixed retail calls. Host tests inject
//! operations into the same algorithm without emulating firmware globals.
//! Target-width fields and volatile reads preserve offsets and callback changes.

use super::media_player_queue_refresh::MediaPlayerQueueOwner;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

type Player = *mut MediaPlayerQueueOwner;
type Class = *mut u8;

#[derive(Clone, Copy)]
struct Ops {
    singleton: unsafe extern "C" fn() -> Class,
    matches: unsafe extern "C" fn(Class) -> bool,
    limit: unsafe extern "C" fn(Class) -> u32,
    index: unsafe extern "C" fn(Player) -> u32,
    release: unsafe extern "C" fn(Player),
    remove: unsafe extern "C" fn(Player, u32),
    class_operation: unsafe extern "C" fn(Class, u32),
    refresh: unsafe extern "C" fn(Player) -> u32,
}

unsafe extern "C" fn matches(owner: Class) -> bool {
    super::class_9400_current_item_matches_media_player::class_9400_current_item_matches_media_player(owner.cast())
}

unsafe extern "C" fn limit(owner: Class) -> u32 {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(Class) -> u32 = core::mem::transmute(0x081b_5e5cusize);
        call(owner)
    }
    #[cfg(not(target_os = "none"))]
    { let _ = owner; panic!("class limit requires retailOS") }
}

unsafe extern "C" fn class_operation(owner: Class, value: u32) {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(Class, u32) -> u32 = core::mem::transmute(0x081b_58c4usize);
        call(owner, value);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (owner, value); panic!("class operation requires retailOS") }
}

unsafe fn slot(player: Player, offset: usize) -> usize {
    let table = read_volatile(addr_of!((*player).vtable));
    read_volatile((table as usize + offset) as *const u32) as usize
}

unsafe extern "C" fn index(player: Player) -> u32 {
    let call: unsafe extern "C" fn(Player) -> u32 = core::mem::transmute(slot(player, 0x158));
    call(player)
}

unsafe extern "C" fn remove(player: Player, value: u32) {
    let call: unsafe extern "C" fn(Player, u32) -> u32 = core::mem::transmute(slot(player, 0x130));
    call(player, value);
}

unsafe extern "C" fn release(player: Player) {
    super::member_release::member_release_if_present(addr_of_mut!((*player).queue).cast());
}

unsafe fn trim(player: Player, ops: Ops) -> u32 {
    let owner = (ops.singleton)();
    if !(ops.matches)(owner) { return 0; }
    let limit = (ops.limit)(owner);
    if (ops.index)(player) < limit { return 0; }
    (ops.release)(player);
    let count = (ops.index)(player).wrapping_sub(limit).wrapping_add(1);
    let mut removed = 0;
    for _ in 0..count {
        (ops.remove)(player, 0);
        (ops.class_operation)((ops.singleton)(), 0);
        removed = 1;
    }
    let source = read_volatile(addr_of!((*player).source_link));
    if source != 0 {
        let final_index = (ops.index)(player);
        write_volatile((source as usize + 0x1c) as *mut u32, final_index);
    }
    (ops.refresh)(player);
    removed
}

/// Trim matching current-item entries and rebuild the player queue.
///
/// # Safety
/// `player` must be a live retail player, including its full embedded queue,
/// valid vtable slots +0x158/+0x130, and any source object through +0x1c.
/// All singleton and queue-helper preconditions remain those of retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_trim_current_item(player: Player) -> u32 {
    trim(player, Ops {
        singleton: super::singletons::singleton_class_9400,
        matches, limit, index, release, remove, class_operation,
        refresh: super::media_player_queue_refresh::media_player_queue_refresh,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;
    std::thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
    #[derive(Default)]
    struct State { matches: bool, limit: u32, indices: Vec<u32>, events: Vec<&'static str>, }
    fn event(name: &'static str) { STATE.with(|s| s.borrow_mut().events.push(name)); }
    unsafe extern "C" fn singleton() -> Class { event("singleton"); core::ptr::null_mut() }
    unsafe extern "C" fn matches(_: Class) -> bool { event("matches"); STATE.with(|s| s.borrow().matches) }
    unsafe extern "C" fn limit(_: Class) -> u32 { event("limit"); STATE.with(|s| s.borrow().limit) }
    unsafe extern "C" fn index(_: Player) -> u32 { event("index"); STATE.with(|s| s.borrow_mut().indices.remove(0)) }
    unsafe extern "C" fn release(_: Player) { event("release"); }
    unsafe extern "C" fn remove(_: Player, value: u32) { assert_eq!(value, 0); event("remove"); }
    unsafe extern "C" fn class_operation(_: Class, value: u32) { assert_eq!(value, 0); event("class"); }
    unsafe extern "C" fn refresh(_: Player) -> u32 { event("refresh"); 99 }
    fn run(matched: bool, limit_value: u32, indices: &[u32]) -> (u32, Vec<&'static str>) {
        STATE.with(|s| *s.borrow_mut() = State { matches: matched, limit: limit_value, indices: indices.to_vec(), events: Vec::new() });
        let mut player: MediaPlayerQueueOwner = unsafe { core::mem::zeroed() };
        let result = unsafe { trim(&mut player, Ops { singleton, matches, limit, index, release, remove, class_operation, refresh }) };
        STATE.with(|s| { let s = s.borrow(); assert!(s.indices.is_empty()); (result, s.events.clone()) })
    }
    #[test]
    fn mismatch_and_unsigned_below_limit_leave_queue_untouched() {
        assert_eq!(run(false, 10, &[]), (0, std::vec!["singleton", "matches"]));
        assert_eq!(run(true, u32::MAX, &[10]), (0, std::vec!["singleton", "matches", "limit", "index"]));
    }
    #[test]
    fn equality_removes_one_and_refresh_result_is_ignored() {
        assert_eq!(run(true, 10, &[10, 10]), (1, std::vec!["singleton", "matches", "limit", "index", "release", "index", "remove", "singleton", "class", "refresh"]));
    }
    #[test]
    fn release_change_controls_count_and_wrapping_zero_still_refreshes() {
        let (result, events) = run(true, 10, &[20, 11]);
        assert_eq!(result, 1);
        assert_eq!(&events[6..], &["remove", "singleton", "class", "remove", "singleton", "class", "refresh"]);
        assert_eq!(run(true, 10, &[10, 9]), (0, std::vec!["singleton", "matches", "limit", "index", "release", "index", "refresh"]));
        assert_eq!(run(true, 0, &[u32::MAX, u32::MAX]).0, 0);
    }
    #[test]
    fn source_receives_fresh_index_after_removal() {
        let Some(source) = crate::testing::try_map_u32_slab(
            crate::testing::hints::MEDIA_PLAYER_TRIM_SOURCE, 0x20,
        ) else { return; };
        STATE.with(|s| *s.borrow_mut() = State {
            matches: true, limit: 10, indices: std::vec![10, 10, 42], events: Vec::new(),
        });
        let mut player: MediaPlayerQueueOwner = unsafe { core::mem::zeroed() };
        player.source_link = source as usize as u32;
        unsafe {
            write_volatile(source.add(0x18).cast::<u32>(), 0x12345678);
            write_volatile(source.add(0x1c).cast::<u32>(), 99);
            assert_eq!(trim(&mut player, Ops { singleton, matches, limit, index, release, remove, class_operation, refresh }), 1);
            assert_eq!(read_volatile(source.add(0x1c).cast::<u32>()), 42);
            assert_eq!(read_volatile(source.add(0x18).cast::<u32>()), 0x12345678);
        }
        STATE.with(|s| assert_eq!(&s.borrow().events[9..], &["index", "refresh"]));
    }
}
