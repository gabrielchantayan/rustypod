//! `view_base_set_geometry` — original: `FUN_0826d850` @ 0x0826d850
//! (44 bytes, Ghidra's extent exact for once: `push {r4,r5,r6,lr}` @
//! 0x0826d850 through `pop {r4,r5,r6,pc}` @ 0x0826d878, and the
//! distinct sibling `FUN_0826d87c` opens with its own
//! `push {r0,r1,r2,r3,r4,r5,r6,lr}` at 0x0826d87c — binary-verified.
//! **22 `bl` call sites, all unconditional, zero predicated forms,
//! zero tail `b`, zero data-word references** — verified by decoding
//! every ARM B/BL word in osos.dec and scanning every word for the
//! address literal; never dispatched virtually, matching Ghidra's 22).
//!
//! # Algorithm
//!
//! The geometry setter of the grand-base view (the class
//! `ui/view_base.rs` constructs; its +0x50..+0x80 `geometry` block is
//! the 0x30-byte field this function overwrites):
//!
//! ```text
//! 0826d850  push {r4,r5,r6,lr}
//! 0826d854  mov  r5, r2          @ redraw
//! 0826d858  mov  r4, r0          @ view
//! 0826d85c  add  r0, r0, #0x50   @ dst = &view->geometry
//! 0826d860  mov  r2, #0x30
//! 0826d864  bl   0x08037df8      @ iram_memcpy_veneer(dst, src, 0x30)
//! 0826d868  cmp  r5, #0
//! 0826d86c  movne r0, r4
//! 0826d870  popne {r4,r5,r6,lr}
//! 0826d874  bne  0x0826db38      @ tail -> geometry_changed(view)
//! 0826d878  pop  {r4,r5,r6,pc}
//! ```
//!
//! Copy the caller's 0x30-byte geometry block over view +0x50 through
//! the ROM memcpy veneer (`bl 0x08037df8` = `iram_memcpy_veneer`, the
//! IRAM mirror of memcpy @ 0x08000188, already ported — called
//! directly per house pattern, the `view_base_construct` precedent),
//! then, when `redraw` is non-zero, tail-call the redraw helper @
//! 0x0826db38. That helper (verified from raw bytes) sets the view's
//! dirty bit (`flags +0x48 |= 0x20`), invalidates the view's own
//! bounds rectangle through the unported region form @ 0x0826ec14,
//! runs the parent chain's vtable +0x128 notification when the view's
//! parent (+0x34) exists and its byte +0xa0 is clear, then marks the
//! vtable +0x5c owner's +0x48 word with 0x40.
//!
//! # Call-site protocol
//!
//! All 22 sites are plain unconditional `bl` with no NULL guard
//! anywhere: callers always hold a live view (the style-attribute
//! applier @ 0x08180194 and the screen builders @ 0x08288218.. pass
//! freshly decoded blocks with `redraw = 1`; the four sites @
//! 0x081802fc.. pass stack blocks likewise). The +0x50 destination is
//! always in-bounds: every view embeds the 0xa4-byte grand-base at
//! offset 0.
//!
//! # Deliberate deviations
//!
//! - The redraw helper `FUN_0826db38` @ 0x0826db38 is unported (not in
//!   names.yaml), so the tail branch becomes a call through the
//!   [`VIEW_BASE_GEOMETRY_CHANGED`] seam, the house pattern: target
//!   builds transmute the retail address 0x0826db38 (hook-ready on
//!   device), host tests install a recording model, and the host
//!   default is inert (the `ui/invalidate.rs` precedent).
//! - The port returns void. The original's r0 on exit is memcpy's
//!   return (the veneer hands back dst/ dst+len) on the redraw==0
//!   path and whatever 0x0826db38 leaves on the other — Ghidra types
//!   both functions void, and all 9 sampled call sites
//!   (0x080966e8/0x0809ef60/0x080a7708/0x080ac0f8/0x081165dc/
//!   0x081802fc/0x08182888/0x08288218/0x0828865c) overwrite r0 with
//!   the very next instruction; no caller can observe it.

use crate::libc::iram_veneers::iram_memcpy_veneer;
use crate::ui::view_base::ViewBase;

/// The unported redraw helper's retail address — original:
/// `FUN_0826db38` @ 0x0826db38. Reached by the seam default on the
/// firmware target only.
#[cfg(target_os = "none")]
const GEOMETRY_CHANGED_ADDRESS: usize = 0x0826_db38;

/// ABI of the redraw helper `FUN_0826db38`: `(view)`. Its exit r0 is
/// scratch no caller consumes (see the module header), so the seam is
/// void.
pub type ViewBaseGeometryChanged = unsafe extern "C" fn(view: *mut ViewBase);

/// Target default: the retail `FUN_0826db38` body at 0x0826db38.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_geometry_changed(view: *mut ViewBase) {
    let changed: unsafe extern "C" fn(*mut ViewBase) =
        unsafe { core::mem::transmute(GEOMETRY_CHANGED_ADDRESS) };
    unsafe { changed(view) };
}

/// Host default: inert. Faithful in that the helper's effects are
/// all side effects on objects host fixtures do not model; the
/// geometry copy below runs regardless.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_geometry_changed(_view: *mut ViewBase) {}

/// The active redraw helper — the dispatch seam for `FUN_0826db38` @
/// 0x0826db38. Host tests install a recording model; the real port
/// replaces the default when it lands.
#[cfg(target_os = "none")]
pub static mut VIEW_BASE_GEOMETRY_CHANGED: ViewBaseGeometryChanged = firmware_geometry_changed;

/// The active redraw helper — inert host default (see above).
#[cfg(not(target_os = "none"))]
pub static mut VIEW_BASE_GEOMETRY_CHANGED: ViewBaseGeometryChanged = missing_geometry_changed;

/// view_base_set_geometry — original: `FUN_0826d850` @ 0x0826d850
/// (44 bytes).
///
/// Copies the caller's 0x30-byte geometry block over the view's
/// +0x50 `geometry` field, then dispatches the redraw helper when
/// `redraw` is non-zero. No NULL guard, matching the original.
///
/// # Safety
/// `view` must point at a writable, 4-byte-aligned [`ViewBase`] (or
/// any object embedding one at offset 0) and `geometry` at a readable
/// 0x30-byte block.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_base_set_geometry(
    view: *mut ViewBase,
    geometry: *const u8,
    redraw: u32,
) {
    iram_memcpy_veneer(
        core::ptr::addr_of_mut!((*view).geometry).cast(),
        geometry,
        0x30,
    );
    if redraw != 0 {
        // Volatile: LLVM must not fold the default in and delete the
        // dispatch, and a host test's installed model must be observed
        // (the ui/invalidate.rs rationale).
        let geometry_changed =
            core::ptr::read_volatile(core::ptr::addr_of!(VIEW_BASE_GEOMETRY_CHANGED));
        geometry_changed(view);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    /// Serializes access to the process-global seam slot.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    static mut SEEN_VIEW: *mut ViewBase = ptr::null_mut();
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn recording_geometry_changed(view: *mut ViewBase) {
        SEEN_VIEW = view;
        CALLS += 1;
    }

    /// Restores the inert host default on drop.
    struct SeamGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                VIEW_BASE_GEOMETRY_CHANGED = missing_geometry_changed;
            }
        }
    }

    fn install_recorder() -> SeamGuard {
        let lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SEEN_VIEW = ptr::null_mut();
            CALLS = 0;
            VIEW_BASE_GEOMETRY_CHANGED = recording_geometry_changed;
        }
        SeamGuard { _lock: lock }
    }

    /// A view whose geometry is poisoned and whose neighbours carry
    /// canaries proving the copy touches exactly +0x50..+0x80.
    fn poisoned_view() -> ViewBase {
        let mut view: ViewBase = unsafe { core::mem::zeroed() };
        view.flags = 0xcafe_cafe;
        view.word_4c = 0x1234_5678;
        view.word_80 = 0x8765_4321;
        for b in &mut view.geometry {
            *b = 0xa5;
        }
        view
    }

    #[test]
    fn copies_the_0x30_byte_block_verbatim_without_redraw() {
        let _guard = install_recorder();
        let mut view = poisoned_view();
        let mut block = [0u8; 0x30];
        for (i, b) in block.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }

        unsafe { view_base_set_geometry(&mut view, block.as_ptr(), 0) };

        assert_eq!(view.geometry, block, "geometry copied verbatim");
        assert_eq!(view.flags, 0xcafe_cafe, "flag word before the block untouched");
        assert_eq!(view.word_4c, 0x1234_5678, "word at +0x4c untouched");
        assert_eq!(view.word_80, 0x8765_4321, "word at +0x80 untouched");
        unsafe {
            assert_eq!(CALLS, 0, "redraw == 0: the helper must not run");
            assert_eq!(SEEN_VIEW, ptr::null_mut());
        }
    }

    #[test]
    fn non_zero_redraw_dispatches_the_helper_once_with_the_view() {
        let _guard = install_recorder();
        let mut view = poisoned_view();
        let block = [0x5au8; 0x30];

        for redraw in [1u32, 2, 0x8000_0000] {
            unsafe {
                CALLS = 0;
                SEEN_VIEW = ptr::null_mut();
                view_base_set_geometry(&mut view, block.as_ptr(), redraw);
                assert_eq!(CALLS, 1, "redraw {redraw:#x}: exactly one dispatch");
                assert_eq!(SEEN_VIEW, &mut view as *mut ViewBase, "r0 = view");
            }
            assert_eq!(view.geometry, block, "the copy runs on the redraw path too");
        }
    }

    #[test]
    fn copy_is_a_full_overwrite_not_a_merge() {
        let _guard = install_recorder();
        let mut view = poisoned_view();
        let block = [0u8; 0x30];

        unsafe { view_base_set_geometry(&mut view, block.as_ptr(), 1) };

        assert_eq!(view.geometry, [0u8; 0x30], "old 0xa5 bytes fully replaced");
        unsafe {
            assert_eq!(CALLS, 1);
        }
    }

    #[test]
    fn default_host_stub_is_inert_and_the_copy_still_runs() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            CALLS = 0;
            VIEW_BASE_GEOMETRY_CHANGED = missing_geometry_changed;
        }
        let mut view = poisoned_view();
        let block = [0x11u8; 0x30];

        unsafe { view_base_set_geometry(&mut view, block.as_ptr(), 1) };

        assert_eq!(view.geometry, block, "copy independent of the helper");
        assert_eq!(unsafe { CALLS }, 0, "no recorder installed, nothing records");
    }
}
