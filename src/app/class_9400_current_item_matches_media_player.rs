//! Class-0x9400 current-item comparison with TPodMediaPlayer.
//!
//! `class_9400_current_item_matches_media_player` — original:
//! `FUN_081b5e64` @ **0x081b5e64**, **196 bytes**
//! (`0x081b5e64..0x081b5f27`; the separately linked next function begins at
//! `0x081b5f28` with `push {r4, r5, r6, lr}`). A complete decode of every ARM
//! `B`/`BL`-immediate in `osos.dec` finds **6 direct inbound `bl` callers**,
//! all unconditional: 0x08179170, 0x0817a814, 0x0817b114, 0x0817d6c0,
//! 0x081f87f8, and 0x0821dc64. There are no predicated calls or direct tail
//! branches.
//!
//! # Algorithm
//!
//! Lock the class-0x9400 tail mutex at +0x220, obtain its current UI element
//! through vtable slot +0xa4, and make a zero-flag ContextScope around it.
//! The scope must be current twice: once before obtaining the global media
//! player and again after. On that path, turn the scope's optional-subject word
//! into a TaggedValue, obtain the media player's current-item value through
//! vtable slot +0x140, construct its TaggedValue through that object's vtable
//! slot +0x08, and compare the two payload pairs. Always drop the stack scope
//! and release the mutex before returning the comparison as a 0/1 result.
//!
//! # Deliberate deviations
//!
//! None on device: the six known direct callees are called as their ports, and
//! the three observed vtable slots remain raw dynamic dispatch. Host builds use
//! replaceable operations only because the live class-0x9400/media-player
//! vtables and app context are firmware state; this makes both stale checks,
//! the cleanup path, and payload comparison testable.

use core::mem::MaybeUninit;
#[cfg(target_os = "none")]
use core::mem;

use crate::app::context_scope::CONTEXT_SCOPE_SIZE;
#[cfg(target_os = "none")]
use crate::app::context_scope::{context_scope_drop, context_scope_init};
#[cfg(target_os = "none")]
use crate::app::singletons::media_player_get;
use crate::cxx::tagged_value::{tagged_value_payload_pair_equal, TaggedValue};
#[cfg(target_os = "none")]
use crate::cxx::tagged_value::tagged_value_from_optional_word4;
use crate::kernel::sync_mutex::CountedMutex;
#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted};
#[cfg(target_os = "none")]
use crate::ui::element_reference::ui_element_reference_is_current;

const LOCK_OFFSET: usize = 0x220;
const CLASS_CURRENT_ELEMENT_SLOT: usize = 0x0a4;
const MEDIA_PLAYER_CURRENT_ITEM_SLOT: usize = 0x140;
const ITEM_TAGGED_VALUE_SLOT: usize = 0x008;

/// Target-layout prefix of the class-0x9400 object used by the predicate.
///
/// The constructor for `singleton_class_9400` makes this 0x22c-byte object and
/// initializes its final CountedMutex at +0x220. The class has no recovered
/// semantic name, so its registry id is retained rather than invented.
#[repr(C)]
pub struct Class9400CurrentItemOwner {
    _before_lock: [u8; LOCK_OFFSET],
    lock: CountedMutex,
}

const _: [u8; LOCK_OFFSET] = [0; core::mem::offset_of!(Class9400CurrentItemOwner, lock)];

#[cfg(target_os = "none")]
unsafe fn class_current_element(owner: *mut Class9400CurrentItemOwner) -> *mut u8 {
    let vtable = owner.cast::<*const usize>().read();
    let callback: unsafe extern "C" fn(*mut Class9400CurrentItemOwner) -> *mut u8 =
        mem::transmute(vtable.add(CLASS_CURRENT_ELEMENT_SLOT / 4).read());
    callback(owner)
}

#[cfg(target_os = "none")]
unsafe fn media_player_current_item(player: *mut u8) -> *mut u8 {
    let vtable = player.cast::<*const usize>().read();
    let callback: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        mem::transmute(vtable.add(MEDIA_PLAYER_CURRENT_ITEM_SLOT / 4).read());
    callback(player)
}

#[cfg(target_os = "none")]
unsafe fn item_tagged_value(output: *mut TaggedValue, item: *mut u8) -> *mut TaggedValue {
    let vtable = item.cast::<*const usize>().read();
    let callback: unsafe extern "C" fn(*mut TaggedValue, *mut u8) -> *mut TaggedValue =
        mem::transmute(vtable.add(ITEM_TAGGED_VALUE_SLOT / 4).read());
    callback(output, item)
}

#[cfg(not(target_os = "none"))]
type LockOperation = unsafe extern "C" fn(*mut CountedMutex);
#[cfg(not(target_os = "none"))]
type ScopeInitOperation = unsafe extern "C" fn(*mut u8, *mut u8, u8) -> *mut u8;
#[cfg(not(target_os = "none"))]
type ScopeCurrentOperation = unsafe extern "C" fn(*const u8) -> u32;
#[cfg(not(target_os = "none"))]
type MediaPlayerGetOperation = unsafe extern "C" fn() -> *mut u8;
#[cfg(not(target_os = "none"))]
type ClassCurrentElementOperation = unsafe extern "C" fn(*mut Class9400CurrentItemOwner) -> *mut u8;
#[cfg(not(target_os = "none"))]
type MediaPlayerCurrentItemOperation = unsafe extern "C" fn(*mut u8) -> *mut u8;
#[cfg(not(target_os = "none"))]
type TaggedValueFromScopeOperation = unsafe extern "C" fn(*mut TaggedValue, *const u32) -> *mut TaggedValue;
#[cfg(not(target_os = "none"))]
type ItemTaggedValueOperation = unsafe extern "C" fn(*mut TaggedValue, *mut u8) -> *mut TaggedValue;
#[cfg(not(target_os = "none"))]
type TaggedValueEqualOperation = unsafe extern "C" fn(*const TaggedValue, *const TaggedValue) -> bool;
#[cfg(not(target_os = "none"))]
type ScopeDropOperation = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Host-only boundaries for the device's app-state and virtual operations.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct Class9400CurrentItemOps {
    pub lock: LockOperation,
    pub current_element: ClassCurrentElementOperation,
    pub scope_init: ScopeInitOperation,
    pub scope_is_current: ScopeCurrentOperation,
    pub media_player_get: MediaPlayerGetOperation,
    pub media_player_current_item: MediaPlayerCurrentItemOperation,
    pub tagged_value_from_scope: TaggedValueFromScopeOperation,
    pub item_tagged_value: ItemTaggedValueOperation,
    pub tagged_value_equal: TaggedValueEqualOperation,
    pub scope_drop: ScopeDropOperation,
    pub unlock: LockOperation,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lock(_lock: *mut CountedMutex) { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scope_init(_scope: *mut u8, _subject: *mut u8, _flag: u8) -> *mut u8 { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scope_current(_scope: *const u8) -> u32 { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_media_player_get() -> *mut u8 { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_class_current_element(_owner: *mut Class9400CurrentItemOwner) -> *mut u8 { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_media_player_current_item(_player: *mut u8) -> *mut u8 { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tagged_value_from_scope(_output: *mut TaggedValue, _scope: *const u32) -> *mut TaggedValue { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_item_tagged_value(_output: *mut TaggedValue, _item: *mut u8) -> *mut TaggedValue { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tagged_value_equal(_left: *const TaggedValue, _right: *const TaggedValue) -> bool { panic!("install class-0x9400 current-item host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scope_drop(_scope: *mut u8) -> *mut u8 { panic!("install class-0x9400 current-item host operations") }

#[cfg(not(target_os = "none"))]
pub const DEFAULT_CLASS_9400_CURRENT_ITEM_OPS: Class9400CurrentItemOps = Class9400CurrentItemOps {
    lock: missing_lock,
    current_element: missing_class_current_element,
    scope_init: missing_scope_init,
    scope_is_current: missing_scope_current,
    media_player_get: missing_media_player_get,
    media_player_current_item: missing_media_player_current_item,
    tagged_value_from_scope: missing_tagged_value_from_scope,
    item_tagged_value: missing_item_tagged_value,
    tagged_value_equal: missing_tagged_value_equal,
    scope_drop: missing_scope_drop,
    unlock: missing_lock,
};

#[cfg(not(target_os = "none"))]
pub static mut CLASS_9400_CURRENT_ITEM_OPS: Class9400CurrentItemOps = DEFAULT_CLASS_9400_CURRENT_ITEM_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> Class9400CurrentItemOps {
    core::ptr::read_volatile(core::ptr::addr_of!(CLASS_9400_CURRENT_ITEM_OPS))
}

/// Returns whether class-0x9400's current UI element represents the media
/// player's current item.
///
/// Original: `FUN_081b5e64` @ 0x081b5e64, 196 bytes, six unconditional
/// inbound `bl` call sites (listed in the module header).
///
/// # Safety
///
/// `owner` must be a live class-0x9400 object through its +0x220 mutex. On
/// device, all three observed vtables and their slot targets must be valid;
/// the scope predicate and TaggedValue constructors retain the firmware's
/// unchecked-pointer preconditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn class_9400_current_item_matches_media_player(
    owner: *mut Class9400CurrentItemOwner,
) -> bool {
    #[cfg(target_os = "none")]
    mutex_lock_counted(core::ptr::addr_of_mut!((*owner).lock));
    #[cfg(not(target_os = "none"))]
    (host_ops().lock)(core::ptr::addr_of_mut!((*owner).lock));

    let mut scope = [0u32; CONTEXT_SCOPE_SIZE / core::mem::size_of::<u32>()];
    #[cfg(target_os = "none")]
    let element = class_current_element(owner);
    #[cfg(not(target_os = "none"))]
    let element = (host_ops().current_element)(owner);

    #[cfg(target_os = "none")]
    context_scope_init(scope.as_mut_ptr().cast(), element, 0);
    #[cfg(not(target_os = "none"))]
    (host_ops().scope_init)(scope.as_mut_ptr().cast(), element, 0);

    #[cfg(target_os = "none")]
    let first_current = ui_element_reference_is_current(scope.as_ptr().cast());
    #[cfg(not(target_os = "none"))]
    let first_current = (host_ops().scope_is_current)(scope.as_ptr().cast());

    let matches = if first_current == 0 {
        false
    } else {
        #[cfg(target_os = "none")]
        let player = media_player_get();
        #[cfg(not(target_os = "none"))]
        let player = (host_ops().media_player_get)();

        #[cfg(target_os = "none")]
        let second_current = ui_element_reference_is_current(scope.as_ptr().cast());
        #[cfg(not(target_os = "none"))]
        let second_current = (host_ops().scope_is_current)(scope.as_ptr().cast());

        if second_current == 0 {
            false
        } else {
            let mut scoped_value = MaybeUninit::<TaggedValue>::uninit();
            let mut player_value = MaybeUninit::<TaggedValue>::uninit();
            #[cfg(target_os = "none")]
            tagged_value_from_optional_word4(scoped_value.as_mut_ptr(), scope.as_ptr());
            #[cfg(not(target_os = "none"))]
            (host_ops().tagged_value_from_scope)(scoped_value.as_mut_ptr(), scope.as_ptr());

            #[cfg(target_os = "none")]
            let item = media_player_current_item(player);
            #[cfg(not(target_os = "none"))]
            let item = (host_ops().media_player_current_item)(player);

            #[cfg(target_os = "none")]
            item_tagged_value(player_value.as_mut_ptr(), item);
            #[cfg(not(target_os = "none"))]
            (host_ops().item_tagged_value)(player_value.as_mut_ptr(), item);

            #[cfg(target_os = "none")]
            { tagged_value_payload_pair_equal(player_value.as_ptr(), scoped_value.as_ptr()) }
            #[cfg(not(target_os = "none"))]
            { (host_ops().tagged_value_equal)(player_value.as_ptr(), scoped_value.as_ptr()) }
        }
    };

    #[cfg(target_os = "none")]
    context_scope_drop(scope.as_mut_ptr().cast());
    #[cfg(not(target_os = "none"))]
    (host_ops().scope_drop)(scope.as_mut_ptr().cast());
    #[cfg(target_os = "none")]
    mutex_unlock_counted(core::ptr::addr_of_mut!((*owner).lock));
    #[cfg(not(target_os = "none"))]
    (host_ops().unlock)(core::ptr::addr_of_mut!((*owner).lock));
    matches
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<&'static str> = Vec::new();
    static mut CURRENT_RESULTS: [u32; 2] = [0; 2];
    static mut CURRENT_CALLS: usize = 0;
    static mut SCOPE_PAYLOAD: u32 = 0;
    static mut PLAYER_PAYLOAD: u32 = 0;
    static mut PLAYER_AUXILIARY: u32 = 0;

    unsafe fn record(call: &'static str) { CALLS.push(call); }

    unsafe extern "C" fn lock_stub(_lock: *mut CountedMutex) { record("lock"); }
    unsafe extern "C" fn unlock_stub(_lock: *mut CountedMutex) { record("unlock"); }
    unsafe extern "C" fn current_element_stub(_owner: *mut Class9400CurrentItemOwner) -> *mut u8 {
        record("element");
        0x11usize as *mut u8
    }
    unsafe extern "C" fn scope_init_stub(scope: *mut u8, _element: *mut u8, flag: u8) -> *mut u8 {
        record("scope_init");
        assert_eq!(flag, 0);
        scope.cast::<u32>().add(1).write(SCOPE_PAYLOAD);
        scope
    }
    unsafe extern "C" fn scope_current_stub(_scope: *const u8) -> u32 {
        record("scope_current");
        let result = CURRENT_RESULTS[CURRENT_CALLS];
        CURRENT_CALLS += 1;
        result
    }
    unsafe extern "C" fn player_get_stub() -> *mut u8 {
        record("player_get");
        0x22usize as *mut u8
    }
    unsafe extern "C" fn player_current_item_stub(player: *mut u8) -> *mut u8 {
        record("player_current_item");
        assert_eq!(player, 0x22usize as *mut u8);
        0x33usize as *mut u8
    }
    unsafe extern "C" fn tagged_value_from_scope_stub(output: *mut TaggedValue, scope: *const u32) -> *mut TaggedValue {
        record("scope_value");
        output.write(TaggedValue { vtable: 0, kind: 1, padding: [0; 3], payload: scope.add(1).read(), auxiliary: 0 });
        output
    }
    unsafe extern "C" fn item_tagged_value_stub(output: *mut TaggedValue, item: *mut u8) -> *mut TaggedValue {
        record("item_value");
        assert_eq!(item, 0x33usize as *mut u8);
        output.write(TaggedValue { vtable: 0, kind: 1, padding: [0; 3], payload: PLAYER_PAYLOAD, auxiliary: PLAYER_AUXILIARY });
        output
    }
    unsafe extern "C" fn tagged_value_equal_stub(left: *const TaggedValue, right: *const TaggedValue) -> bool {
        record("equal");
        tagged_value_payload_pair_equal(left, right)
    }
    unsafe extern "C" fn scope_drop_stub(_scope: *mut u8) -> *mut u8 {
        record("scope_drop");
        core::ptr::null_mut()
    }

    const TEST_OPS: Class9400CurrentItemOps = Class9400CurrentItemOps {
        lock: lock_stub,
        current_element: current_element_stub,
        scope_init: scope_init_stub,
        scope_is_current: scope_current_stub,
        media_player_get: player_get_stub,
        media_player_current_item: player_current_item_stub,
        tagged_value_from_scope: tagged_value_from_scope_stub,
        item_tagged_value: item_tagged_value_stub,
        tagged_value_equal: tagged_value_equal_stub,
        scope_drop: scope_drop_stub,
        unlock: unlock_stub,
    };

    unsafe fn run(first_current: u32, second_current: u32, scope_payload: u32, player_payload: u32, player_auxiliary: u32) -> bool {
        CALLS.clear();
        CURRENT_RESULTS = [first_current, second_current];
        CURRENT_CALLS = 0;
        SCOPE_PAYLOAD = scope_payload;
        PLAYER_PAYLOAD = player_payload;
        PLAYER_AUXILIARY = player_auxiliary;
        CLASS_9400_CURRENT_ITEM_OPS = TEST_OPS;
        let mut owner = MaybeUninit::<Class9400CurrentItemOwner>::uninit();
        class_9400_current_item_matches_media_player(owner.as_mut_ptr())
    }

    #[test]
    fn stale_scope_short_circuits_but_still_releases_everything() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            assert!(!run(0, 1, 0x33, 0x33, 0));
            assert_eq!(CALLS, ["lock", "element", "scope_init", "scope_current", "scope_drop", "unlock"]);
        }
    }

    #[test]
    fn second_staleness_check_gates_media_player_lookup() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            assert!(!run(1, 0, 0x33, 0x33, 0));
            assert_eq!(CALLS, ["lock", "element", "scope_init", "scope_current", "player_get", "scope_current", "scope_drop", "unlock"]);
        }
    }

    #[test]
    fn matching_payload_pair_returns_true_and_auxiliary_mismatch_returns_false() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            assert!(run(1, 1, 0xa1b2_c3d4, 0xa1b2_c3d4, 0));
            assert_eq!(CALLS, ["lock", "element", "scope_init", "scope_current", "player_get", "scope_current", "scope_value", "player_current_item", "item_value", "equal", "scope_drop", "unlock"]);
            assert!(!run(1, 1, 0xa1b2_c3d4, 0xa1b2_c3d4, 7));
        }
    }
}
