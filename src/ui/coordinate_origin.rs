//! Updating a drawable owner's coordinate origin.
//!
//! `coordinate_owner_set_origin` — original: `FUN_0828c600` @ **0x0828c600**
//! (132 bytes; extent verified through the next `push {r4,r5,r6,lr}` at
//! 0x0828c684). Raw decoding of every ARM `B`/`BL` word in `osos.dec` finds
//! exactly 25 direct call sites: 19 unconditional `bl` and 6 `blne`, with no
//! tail branches. The predicated callers guard nullable drawable owners; this
//! routine itself immediately dereferences both arguments.
//!
//! # Algorithm
//!
//! When the owner is active (+0xee) and has a render context (+0x00), copy its
//! local rectangle (+0x20), offset the copy by the old horizontal/vertical
//! origin (+0x30/+0x34), and submit that old screen-space rectangle to the
//! context's dirty-region operation (the still-unported `FUN_0828d9b4`). Then
//! copy the supplied `Point` into +0x30/+0x34, mark dirty and origin-changed
//! bytes (+0xec/+0xed), and, unless the command index at +0xfc is -1, invoke
//! `FUN_0828d110` to refresh the owner.
//!
//! # Deliberate deviations
//!
//! `FUN_0828d9b4` and `FUN_0828d110` are absent from `names.yaml`, so this
//! port reaches them through volatile seams. Device builds call their verified
//! retail addresses; host tests install recording models. The former is known
//! to union its rectangle into render-context +0xdc under the +0xd4 lock; the
//! latter's concrete identity remains unresolved, so its seam is named only
//! for its proven role after an origin update.

use core::mem::size_of;
use core::ptr;

use crate::drivers::display::{display_get_layer, Display};
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};
use crate::ui::rect::{rect_offset, Point, Rect};

/// ABI of the unported `FUN_0828d9b4`: add `rect` to `render_context`'s dirty
/// region. The source rectangle is read but not modified.
pub type RenderContextInvalidateRect = unsafe extern "C" fn(render_context: *mut u8, rect: *const Rect);

/// ABI of `FUN_0828d110`, called after changing an owner with a live command
/// index. Its only proven input is the owner pointer; the stock body ignores
/// r1 after its caller sets it to zero.
pub type CoordinateOwnerRefresh = unsafe extern "C" fn(owner: *mut u8);

/// ABI of `FUN_0828d5f4`, which completes and clears the owner's pending
/// coordinate handoff before changing its selected display layer.
pub type CoordinateOwnerFlushPending = unsafe extern "C" fn(owner: *mut u8);

/// ABI of `FUN_081204a0`, which commits a selected layer's pending state.
pub type LayerCommitPendingState = unsafe extern "C" fn(layer: *mut u8) -> u32;

/// ABI of the separately ported `rect_offset` helper at 0x0826c574.
#[cfg(target_os = "none")]
type RectOffset = unsafe extern "C" fn(rect: *mut Rect, dx: i32, dy: i32);

/// Volatile indirection retains the original call to the hot rectangle helper
/// rather than allowing LLVM to inline its four additions into this port.
#[cfg(target_os = "none")]
static RECT_OFFSET: RectOffset = rect_offset;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn offset_rect(rect: *mut Rect, dx: i32, dy: i32) {
    let offset = ptr::read_volatile(ptr::addr_of!(RECT_OFFSET));
    offset(rect, dx, dy);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn offset_rect(rect: *mut Rect, dx: i32, dy: i32) {
    rect_offset(rect, dx, dy);
}


#[cfg(target_os = "none")]
const RENDER_CONTEXT_INVALIDATE_RECT_ADDRESS: usize = 0x0828_d9b4;
#[cfg(target_os = "none")]
const COORDINATE_OWNER_REFRESH_ADDRESS: usize = 0x0828_d110;
#[cfg(target_os = "none")]
const COORDINATE_OWNER_FLUSH_PENDING_ADDRESS: usize = 0x0828_d5f4;
#[cfg(target_os = "none")]
const LAYER_COMMIT_PENDING_STATE_ADDRESS: usize = 0x0812_04a0;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_invalidate_rect(render_context: *mut u8, rect: *const Rect) {
    let invalidate: RenderContextInvalidateRect =
        core::mem::transmute(RENDER_CONTEXT_INVALIDATE_RECT_ADDRESS);
    invalidate(render_context, rect);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_coordinate_owner_refresh(owner: *mut u8) {
    let refresh: CoordinateOwnerRefresh = core::mem::transmute(COORDINATE_OWNER_REFRESH_ADDRESS);
    refresh(owner);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_coordinate_owner_flush_pending(owner: *mut u8) {
    let flush_pending: CoordinateOwnerFlushPending =
        core::mem::transmute(COORDINATE_OWNER_FLUSH_PENDING_ADDRESS);
    flush_pending(owner);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_layer_commit_pending_state(layer: *mut u8) -> u32 {
    let commit_pending: LayerCommitPendingState =
        core::mem::transmute(LAYER_COMMIT_PENDING_STATE_ADDRESS);
    commit_pending(layer)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_invalidate_rect(_render_context: *mut u8, _rect: *const Rect) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_coordinate_owner_refresh(_owner: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_coordinate_owner_flush_pending(_owner: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_layer_commit_pending_state(_layer: *mut u8) -> u32 {
    0
}

/// The unported dirty-region operation. Firmware calls 0x0828d9b4; host tests
/// replace this with a model rather than pretending the dirty region changed.
#[cfg(target_os = "none")]
pub static mut RENDER_CONTEXT_INVALIDATE_RECT: RenderContextInvalidateRect = firmware_invalidate_rect;
#[cfg(not(target_os = "none"))]
pub static mut RENDER_CONTEXT_INVALIDATE_RECT: RenderContextInvalidateRect = missing_invalidate_rect;

/// The unported follow-up operation after an origin change. Firmware calls
/// 0x0828d110; host tests replace this with a recording model.
#[cfg(target_os = "none")]
pub static mut COORDINATE_OWNER_REFRESH: CoordinateOwnerRefresh = firmware_coordinate_owner_refresh;
#[cfg(not(target_os = "none"))]
pub static mut COORDINATE_OWNER_REFRESH: CoordinateOwnerRefresh = missing_coordinate_owner_refresh;

/// The unported handoff completion at `FUN_0828d5f4`. Firmware calls its
/// verified retail address; host tests use a recorder.
#[cfg(target_os = "none")]
pub static mut COORDINATE_OWNER_FLUSH_PENDING: CoordinateOwnerFlushPending =
    firmware_coordinate_owner_flush_pending;
#[cfg(not(target_os = "none"))]
pub static mut COORDINATE_OWNER_FLUSH_PENDING: CoordinateOwnerFlushPending =
    missing_coordinate_owner_flush_pending;

/// The unported layer-state commit at `FUN_081204a0`. Firmware calls its
/// verified retail address; host tests use a recorder.
#[cfg(target_os = "none")]
pub static mut LAYER_COMMIT_PENDING_STATE: LayerCommitPendingState =
    firmware_layer_commit_pending_state;
#[cfg(not(target_os = "none"))]
pub static mut LAYER_COMMIT_PENDING_STATE: LayerCommitPendingState =
    missing_layer_commit_pending_state;

/// RetailOS's 32-bit layout. Named fields preserve aligned `ldr`/`str` access
/// to each word on ARMv5TE.
#[cfg(target_os = "none")]
#[repr(C)]
struct TargetCoordinateOwner {
    render_context: u32,
    _before_bounds: [u32; 7],
    bounds: Rect,
    origin: Point,
    _before_opacity: [u8; 7],
    opacity: u8,
    _before_dirty: [u8; 0xec - 0x40],
    dirty: u8,
    origin_changed: u8,
    active: u8,
    _before_command_index: [u8; 0xfc - 0xef],
    command_index: i32,
}

#[cfg(target_os = "none")]
const _: () = assert!(size_of::<TargetCoordinateOwner>() == 0x100);

/// Host fixtures need a native-width context pointer while every later field
/// retains its retail byte offset. Packed access is host-only; ARM uses
/// [`TargetCoordinateOwner`] above.
#[cfg(not(target_os = "none"))]
#[repr(C, packed)]
struct HostCoordinateOwner {
    render_context: *mut u8,
    _before_bounds: [u8; 0x20 - size_of::<*mut u8>()],
    bounds: Rect,
    origin: Point,
    _before_opacity: [u8; 7],
    opacity: u8,
    _before_dirty: [u8; 0xec - 0x40],
    dirty: u8,
    origin_changed: u8,
    active: u8,
    _before_command_index: [u8; 0xfc - 0xef],
    command_index: i32,
}

#[cfg(not(target_os = "none"))]
const _: () = assert!(size_of::<HostCoordinateOwner>() == 0x100);

#[inline(always)]
unsafe fn invalidate_rect() -> RenderContextInvalidateRect {
    ptr::read_volatile(ptr::addr_of!(RENDER_CONTEXT_INVALIDATE_RECT))
}

#[inline(always)]
unsafe fn coordinate_owner_refresh() -> CoordinateOwnerRefresh {
    ptr::read_volatile(ptr::addr_of!(COORDINATE_OWNER_REFRESH))
}

#[inline(always)]
unsafe fn coordinate_owner_flush_pending() -> CoordinateOwnerFlushPending {
    ptr::read_volatile(ptr::addr_of!(COORDINATE_OWNER_FLUSH_PENDING))
}

#[inline(always)]
unsafe fn layer_commit_pending_state() -> LayerCommitPendingState {
    ptr::read_volatile(ptr::addr_of!(LAYER_COMMIT_PENDING_STATE))
}

#[inline(always)]
unsafe fn owner_word(owner: *mut u8, offset: usize) -> u32 {
    (owner.add(offset) as *const u32).read_volatile()
}

#[inline(always)]
unsafe fn set_owner_word(owner: *mut u8, offset: usize, value: u32) {
    (owner.add(offset) as *mut u32).write_volatile(value);
}

/// coordinate_owner_set_opacity — original: `FUN_0828c534` @ **0x0828c534**
/// (36 bytes; extent verified through `bx lr` at 0x0828c554, immediately
/// before the distinct next function at 0x0828c558). Decoding every ARM
/// `B`/`BL` word in `osos.dec` finds 9 direct `bl` call sites: 8
/// unconditional and 1 `blne`. One additional unconditional `b` tail-call
/// site at 0x0808ea68 supplies the opacity from a descriptor word.
///
/// # Algorithm
///
/// Stores the supplied opacity byte at owner +0x3f, marks the owner dirty and
/// origin-changed (+0xec/+0xed), then refreshes it unless its command index
/// (+0xfc) is -1. The body has no NULL guard; callers must provide an owner.
///
/// # Deliberate deviations
///
/// None. The existing volatile refresh seam reaches verified retail address
/// 0x0828d110 on-device and a recording model in host tests.
#[cfg(target_os = "none")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn coordinate_owner_set_opacity(owner: *mut u8, opacity: u8) {
    let owner_fields = owner.cast::<TargetCoordinateOwner>();
    ptr::addr_of_mut!((*owner_fields).opacity).write_volatile(opacity);
    ptr::addr_of_mut!((*owner_fields).dirty).write_volatile(1);
    ptr::addr_of_mut!((*owner_fields).origin_changed).write_volatile(1);
    if ptr::addr_of!((*owner_fields).command_index).read_volatile() != -1 {
        coordinate_owner_refresh()(owner);
    }
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn coordinate_owner_set_opacity(owner: *mut u8, opacity: u8) {
    let owner_fields = owner.cast::<HostCoordinateOwner>();
    ptr::addr_of_mut!((*owner_fields).opacity).write_unaligned(opacity);
    ptr::addr_of_mut!((*owner_fields).dirty).write_unaligned(1);
    ptr::addr_of_mut!((*owner_fields).origin_changed).write_unaligned(1);
    if ptr::addr_of!((*owner_fields).command_index).read_unaligned() != -1 {
        coordinate_owner_refresh()(owner);
    }
}


/// ARM form of [`coordinate_owner_set_origin`].
#[cfg(target_os = "none")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn coordinate_owner_set_origin(owner: *mut u8, origin: *const Point) {
    let owner_fields = owner.cast::<TargetCoordinateOwner>();
    if ptr::addr_of!((*owner_fields).active).read() != 0 {
        let render_context = ptr::addr_of!((*owner_fields).render_context).read() as usize as *mut u8;
        if !render_context.is_null() {
            let mut old_bounds = ptr::addr_of!((*owner_fields).bounds).read();
            offset_rect(
                &mut old_bounds,
                ptr::addr_of!((*owner_fields).origin.x).read(),
                ptr::addr_of!((*owner_fields).origin.y).read(),
            );
            invalidate_rect()(render_context, &old_bounds);
        }
    }

    let origin = origin.read();
    ptr::addr_of_mut!((*owner_fields).origin).write(origin);
    ptr::addr_of_mut!((*owner_fields).dirty).write(1);
    ptr::addr_of_mut!((*owner_fields).origin_changed).write(1);
    if ptr::addr_of!((*owner_fields).command_index).read() != -1 {
        coordinate_owner_refresh()(owner);
    }
}

/// Host form of [`coordinate_owner_set_origin`].
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn coordinate_owner_set_origin(owner: *mut u8, origin: *const Point) {
    let owner_fields = owner.cast::<HostCoordinateOwner>();
    if ptr::addr_of!((*owner_fields).active).read_unaligned() != 0 {
        let render_context = ptr::addr_of!((*owner_fields).render_context).read_unaligned();
        if !render_context.is_null() {
            let mut old_bounds = ptr::addr_of!((*owner_fields).bounds).read_unaligned();
            let old_origin = ptr::addr_of!((*owner_fields).origin).read_unaligned();
            rect_offset(&mut old_bounds, old_origin.x, old_origin.y);
            invalidate_rect()(render_context, &old_bounds);
        }
    }

    ptr::addr_of_mut!((*owner_fields).origin).write_unaligned(origin.read());
    ptr::addr_of_mut!((*owner_fields).dirty).write_unaligned(1);
    ptr::addr_of_mut!((*owner_fields).origin_changed).write_unaligned(1);
    if ptr::addr_of!((*owner_fields).command_index).read_unaligned() != -1 {
        coordinate_owner_refresh()(owner);
    }
}

/// coordinate_owner_select_display_layer — original: `FUN_0828cccc` @
/// **0x0828cccc** (132 code bytes plus the 4-byte literal pool at
/// 0x0828cd50; the next function starts at 0x0828cd54). Decoding every ARM
/// `B`/`BL` word in `osos.dec` finds exactly **11 unconditional `bl` call
/// sites**, with no predicated calls or tail branches.
///
/// When the owner has a live presentation (+0x54), takes its recursive mutex
/// (+0x110), completes any pending coordinate handoff, and, for selection
/// indices 0 through 4, copies that index's opaque 32-bit selector from the
/// literal-referenced table at 0x083ecb28. It stores the full selector at
/// +0xfc and the selection index at +0x100, gets the display layer named by
/// the selector's low byte from the display pointer at +0xf4, commits that
/// layer's pending state, and refreshes the owner. Invalid indices still
/// complete the pending handoff under the mutex but leave all selection fields
/// and the display untouched.
///
/// # Deliberate deviations
///
/// `FUN_0828d5f4` and `FUN_081204a0` are absent from `names.yaml`, so their
/// calls use volatile seams to their verified retail addresses on-device and
/// recording models in host tests. `display_get_layer` and the recursive
/// mutex pair are already ported and are called directly. The third ABI
/// argument is forwarded by the stock caller into `r1` for
/// `FUN_0828d110`, but raw decoding of that callee proves it is never read;
/// the port therefore preserves its ABI but deliberately ignores it.
///
/// The stock body copies the five immutable table words through the ROM
/// `memcpy` veneer before indexing them. This port reads the same raw words
/// from an immutable Rust table instead; neither path exposes or mutates the
/// scratch copy.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn coordinate_owner_select_display_layer(
    owner: *mut u8,
    selection: u32,
    _refresh_hint: u32,
) {
    const LAYER_SELECTORS: [u32; 5] = [
        0x1382_20ff,
        0x11a0_0b82,
        0x11a0_f00e,
        0xe59f_0000,
        0xe1a0_f00e,
    ];

    if owner_word(owner, 0x54) == 0 {
        return;
    }

    let mutex = owner.add(0x110).cast::<PosixMutex>();
    posix_mutex_lock(mutex);
    coordinate_owner_flush_pending()(owner);

    if selection < LAYER_SELECTORS.len() as u32 {
        let layer_selector = LAYER_SELECTORS[selection as usize];
        set_owner_word(owner, 0xfc, layer_selector);
        set_owner_word(owner, 0x100, selection);
        let display = owner_word(owner, 0xf4) as usize as *mut Display;
        let layer = display_get_layer(display, layer_selector & 0xff);
        layer_commit_pending_state()(layer);
        coordinate_owner_refresh()(owner);
    }

    posix_mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use crate::drivers::display::Display;
    use crate::testing::{hints, try_map_u32_slab};


    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut INVALIDATED_CONTEXT: *mut u8 = ptr::null_mut();
    static mut INVALIDATED_RECT: Rect = Rect { top: 0, left: 0, bottom: 0, right: 0 };
    static mut INVALIDATE_CALLS: u32 = 0;
    static mut REFRESHED_OWNER: *mut u8 = ptr::null_mut();
    static mut REFRESH_CALLS: u32 = 0;
    static mut FLUSHED_OWNER: *mut u8 = ptr::null_mut();
    static mut FLUSH_CALLS: u32 = 0;
    static mut COMMITTED_LAYER: *mut u8 = ptr::null_mut();
    static mut COMMIT_CALLS: u32 = 0;
    static mut EVENT_LOG: [u8; 3] = [0; 3];
    static mut EVENT_COUNT: usize = 0;

    unsafe fn record_event(event: u8) {
        EVENT_LOG[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }


    unsafe extern "C" fn record_invalidation(render_context: *mut u8, rect: *const Rect) {
        INVALIDATED_CONTEXT = render_context;
        INVALIDATED_RECT = rect.read();
        INVALIDATE_CALLS += 1;
    }

    unsafe extern "C" fn record_refresh(owner: *mut u8) {
        REFRESHED_OWNER = owner;
        REFRESH_CALLS += 1;
        record_event(3);
    }

    unsafe extern "C" fn record_flush(owner: *mut u8) {
        FLUSHED_OWNER = owner;
        FLUSH_CALLS += 1;
        record_event(1);
    }

    unsafe extern "C" fn record_commit(layer: *mut u8) -> u32 {
        COMMITTED_LAYER = layer;
        COMMIT_CALLS += 1;
        record_event(2);
        0
    }

    struct SeamGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                RENDER_CONTEXT_INVALIDATE_RECT = missing_invalidate_rect;
                COORDINATE_OWNER_REFRESH = missing_coordinate_owner_refresh;
                COORDINATE_OWNER_FLUSH_PENDING = missing_coordinate_owner_flush_pending;
                LAYER_COMMIT_PENDING_STATE = missing_layer_commit_pending_state;
            }
        }
    }

    fn install_recorders() -> SeamGuard {
        let lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            INVALIDATED_CONTEXT = ptr::null_mut();
            INVALIDATED_RECT = Rect::default();
            INVALIDATE_CALLS = 0;
            REFRESHED_OWNER = ptr::null_mut();
            REFRESH_CALLS = 0;
            FLUSHED_OWNER = ptr::null_mut();
            FLUSH_CALLS = 0;
            COMMITTED_LAYER = ptr::null_mut();
            COMMIT_CALLS = 0;
            EVENT_LOG = [0; 3];
            EVENT_COUNT = 0;
            RENDER_CONTEXT_INVALIDATE_RECT = record_invalidation;
            COORDINATE_OWNER_REFRESH = record_refresh;
            COORDINATE_OWNER_FLUSH_PENDING = record_flush;
            LAYER_COMMIT_PENDING_STATE = record_commit;
        }
        SeamGuard { _lock: lock }
    }

    unsafe fn owner_fields(storage: &mut [u8; 0x100]) -> *mut HostCoordinateOwner {
        storage.as_mut_ptr().cast()
    }

    unsafe fn set_context(owner: *mut HostCoordinateOwner, context: *mut u8) {
        ptr::addr_of_mut!((*owner).render_context).write_unaligned(context);
    }

    unsafe fn set_bounds(owner: *mut HostCoordinateOwner, bounds: Rect) {
        ptr::addr_of_mut!((*owner).bounds).write_unaligned(bounds);
    }

    unsafe fn set_origin(owner: *mut HostCoordinateOwner, origin: Point) {
        ptr::addr_of_mut!((*owner).origin).write_unaligned(origin);
    }

    unsafe fn set_active(owner: *mut HostCoordinateOwner, active: u8) {
        ptr::addr_of_mut!((*owner).active).write_unaligned(active);
    }

    unsafe fn set_command_index(owner: *mut HostCoordinateOwner, index: i32) {
        ptr::addr_of_mut!((*owner).command_index).write_unaligned(index);
    }

    #[test]
    fn opacity_write_marks_state_without_refresh_for_command_index_minus_one() {
        let _guard = install_recorders();
        let mut storage = [0u8; 0x100];
        let owner = unsafe { owner_fields(&mut storage) };
        unsafe {
            set_command_index(owner, -1);

            coordinate_owner_set_opacity(owner.cast(), 0);

            assert_eq!(ptr::addr_of!((*owner).opacity).read_unaligned(), 0);
            assert_eq!(ptr::addr_of!((*owner).dirty).read_unaligned(), 1);
            assert_eq!(ptr::addr_of!((*owner).origin_changed).read_unaligned(), 1);
            assert_eq!(REFRESH_CALLS, 0);
        }
    }

    #[test]
    fn opacity_write_refreshes_live_owner_after_storing_full_opacity() {
        let _guard = install_recorders();
        let mut storage = [0u8; 0x100];
        let owner = unsafe { owner_fields(&mut storage) };
        unsafe {
            set_command_index(owner, i32::MIN);

            coordinate_owner_set_opacity(owner.cast(), 0xff);

            assert_eq!(ptr::addr_of!((*owner).opacity).read_unaligned(), 0xff);
            assert_eq!(ptr::addr_of!((*owner).dirty).read_unaligned(), 1);
            assert_eq!(ptr::addr_of!((*owner).origin_changed).read_unaligned(), 1);
            assert_eq!(REFRESH_CALLS, 1);
            assert_eq!(REFRESHED_OWNER, owner.cast());
        }
    }

    #[repr(align(4))]
    struct LayerSelectionOwner([u8; 0x128]);

    unsafe fn display_layer_slot(display: *mut Display, index: usize) -> *mut *mut u8 {
        ptr::addr_of_mut!((*display).layers).cast::<*mut u8>().add(index)
    }

    #[test]
    fn invalidates_old_screen_bounds_before_replacing_the_origin() {
        let _guard = install_recorders();
        let mut storage = [0u8; 0x100];
        let owner = unsafe { owner_fields(&mut storage) };
        let mut context = [0u8; 1];
        unsafe {
            set_context(owner, context.as_mut_ptr());
            set_bounds(owner, Rect { top: -4, left: 10, bottom: 20, right: 40 });
            set_origin(owner, Point { x: 7, y: -3 });
            set_active(owner, 1);
            set_command_index(owner, -1);
        }
        let new_origin = Point { x: -12, y: 15 };

        unsafe { coordinate_owner_set_origin(owner.cast(), &new_origin) };

        unsafe {
            assert_eq!(INVALIDATE_CALLS, 1);
            assert_eq!(INVALIDATED_CONTEXT, context.as_mut_ptr());
            assert_eq!(INVALIDATED_RECT, Rect { top: -7, left: 17, bottom: 17, right: 47 });
            assert_eq!(ptr::addr_of!((*owner).origin).read_unaligned(), new_origin);
            assert_eq!(ptr::addr_of!((*owner).dirty).read_unaligned(), 1);
            assert_eq!(ptr::addr_of!((*owner).origin_changed).read_unaligned(), 1);
            assert_eq!(REFRESH_CALLS, 0, "-1 suppresses the follow-up refresh");
        }
    }

    #[test]
    fn inactive_or_contextless_owner_skips_old_bounds_invalidation() {
        let _guard = install_recorders();
        for (active, context) in [(0, true), (1, false)] {
            let mut storage = [0u8; 0x100];
            let owner = unsafe { owner_fields(&mut storage) };
            let mut context_storage = [0u8; 1];
            unsafe {
                set_context(owner, if context { context_storage.as_mut_ptr() } else { ptr::null_mut() });
                set_bounds(owner, Rect { top: 1, left: 2, bottom: 3, right: 4 });
                set_origin(owner, Point { x: 5, y: 6 });
                set_active(owner, active);
                set_command_index(owner, -1);
                coordinate_owner_set_origin(owner.cast(), &Point { x: 9, y: -10 });
                assert_eq!(ptr::addr_of!((*owner).origin).read_unaligned(), Point { x: 9, y: -10 });
                assert_eq!(ptr::addr_of!((*owner).dirty).read_unaligned(), 1);
                assert_eq!(ptr::addr_of!((*owner).origin_changed).read_unaligned(), 1);
            }
        }
        assert_eq!(unsafe { INVALIDATE_CALLS }, 0);
        assert_eq!(unsafe { REFRESH_CALLS }, 0);
    }

    #[test]
    fn live_command_index_refreshes_after_storing_new_origin() {
        let _guard = install_recorders();
        let mut storage = [0u8; 0x100];
        let owner = unsafe { owner_fields(&mut storage) };
        unsafe {
            set_active(owner, 0);
            set_command_index(owner, 0xffff);
            coordinate_owner_set_origin(owner.cast(), &Point { x: i32::MIN, y: i32::MAX });
            assert_eq!(REFRESH_CALLS, 1);
            assert_eq!(REFRESHED_OWNER, owner.cast());
            assert_eq!(ptr::addr_of!((*owner).origin).read_unaligned(), Point { x: i32::MIN, y: i32::MAX });
        }
    }
    #[test]
    fn selection_commits_the_table_selected_layer_before_refreshing() {
        let _guard = install_recorders();
        let Some(display_storage) =
            try_map_u32_slab(hints::COORDINATE_OWNER_DISPLAY_LAYER, 0x1000)
        else {
            return;
        };
        let mut owner_storage = LayerSelectionOwner([0; 0x128]);
        let owner = owner_storage.0.as_mut_ptr();
        let mut layer = [0u8; 1];

        unsafe {
            ptr::write_bytes(display_storage, 0, 0x1000);
            let display = display_storage.cast::<Display>();
            display_layer_slot(display, 0xff).write_volatile(layer.as_mut_ptr());
            set_owner_word(owner, 0x54, 1);
            set_owner_word(owner, 0xf4, display as usize as u32);
            set_owner_word(owner, 0xfc, 0xfeed_face);
            set_owner_word(owner, 0x100, 0xdead_beef);

            coordinate_owner_select_display_layer(owner, 0, 0x1234_5678);

            assert_eq!(FLUSH_CALLS, 1);
            assert_eq!(FLUSHED_OWNER, owner);
            assert_eq!(COMMIT_CALLS, 1);
            assert_eq!(COMMITTED_LAYER, layer.as_mut_ptr());
            assert_eq!(REFRESH_CALLS, 1);
            assert_eq!(REFRESHED_OWNER, owner);
            assert_eq!(owner_word(owner, 0xfc), 0x1382_20ff);
            assert_eq!(owner_word(owner, 0x100), 0);
            assert_eq!(&EVENT_LOG[..EVENT_COUNT], &[1, 2, 3]);
        }
    }

    #[test]
    fn invalid_selection_only_flushes_the_pending_handoff() {
        let _guard = install_recorders();
        let mut owner_storage = LayerSelectionOwner([0; 0x128]);
        let owner = owner_storage.0.as_mut_ptr();

        unsafe {
            set_owner_word(owner, 0x54, 1);
            set_owner_word(owner, 0xfc, 0xfeed_face);
            set_owner_word(owner, 0x100, 0xdead_beef);

            coordinate_owner_select_display_layer(owner, 5, 0);

            assert_eq!(FLUSH_CALLS, 1);
            assert_eq!(COMMIT_CALLS, 0);
            assert_eq!(REFRESH_CALLS, 0);
            assert_eq!(owner_word(owner, 0xfc), 0xfeed_face);
            assert_eq!(owner_word(owner, 0x100), 0xdead_beef);
            assert_eq!(&EVENT_LOG[..EVENT_COUNT], &[1]);
        }
    }

    #[test]
    fn owner_without_presentation_is_a_complete_noop() {
        let _guard = install_recorders();
        let mut owner_storage = LayerSelectionOwner([0; 0x128]);
        let owner = owner_storage.0.as_mut_ptr();

        unsafe {
            set_owner_word(owner, 0xfc, 0xfeed_face);
            set_owner_word(owner, 0x100, 0xdead_beef);

            coordinate_owner_select_display_layer(owner, 0, 0);

            assert_eq!(FLUSH_CALLS, 0);
            assert_eq!(COMMIT_CALLS, 0);
            assert_eq!(REFRESH_CALLS, 0);
            assert_eq!(owner_word(owner, 0xfc), 0xfeed_face);
            assert_eq!(owner_word(owner, 0x100), 0xdead_beef);
        }
    }

}
