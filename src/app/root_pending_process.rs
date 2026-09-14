//! Root pending-work processor.
//!
//! `root_pending_process` — original: `FUN_08112bbc` @ **0x08112bbc**
//! (56 bytes of code plus its `0x0001d4c0` literal-pool word @ 0x08112bf4 =
//! **60 bytes** of true extent, `0x08112bbc..0x08112bf8`; the separately
//! linked next function starts at 0x08112bf8). Ghidra's reported 56-byte
//! extent excludes the pool word used by `ldr r1,[pc,#4]`.
//!
//! Raw-image decoding finds exactly **six direct `bl` call sites**: four
//! unconditional (`0x081147cc`, `0x0812f390`, `0x0813139c`, `0x08219a00`) and
//! two `blne` (`0x081161bc`, `0x08232bfc`). There are no direct `b` sites.
//! The predicated callers establish that some call paths gate processing on a
//! prior non-zero condition; this function itself has no corresponding NULL
//! guard. One aligned data word at `0x0898d9d0` contains this address, but its
//! dispatch identity is unrecovered and deliberately not invented.
//!
//! # Algorithm
//!
//! Query the root's `+0x888` sub-object through the ported slot-`+0x190`
//! veneer. Independently invoke that sub-object's vtable slot `+0xf0`. A zero
//! query result returns only after that callback. Otherwise obtain the
//! class-0x8c00 singleton and invoke its two-minute (`0x1d4c0` ms) timer
//! refresh / event-post method.
//!
//! # Deliberate deviations
//!
//! ARM vtable entries are four-byte words, while host callback pointers are
//! native-width; the typed host vtable therefore selects word index 60. The
//! ARM tail branch to `class_8c00_rearm_timer_post_0x11` is a normal direct
//! call. The slot-`+0x190` veneer is now called directly, with no dispatch seam.

use crate::app::class_8c00::class_8c00_rearm_timer_post_0x11;
use crate::app::singletons::singleton_class_8c00;
use crate::app::root_slot_190_query::root_slot_190_query;

/// ARMv5TE word index for vtable offset `+0xf0`.
pub const ROOT_PENDING_PROCESS_SLOT: usize = 0xf0 / 4;

/// ARM byte offset of the root pointer to its pending-work sub-object.
pub const ROOT_PENDING_SUBOBJECT_OFFSET: usize = 0x888;

/// ABI of the unrecovered root sub-object vtable callback at `+0xf0`.
pub type RootPendingProcessCallback = unsafe extern "C" fn(*mut RootPendingProcessSubobject);

/// Root prefix consumed by [`root_pending_process`].
///
/// The `pending_subobject` word is at `+0x888` on the ARM target. Native host
/// pointer width is intentional so host fixtures can carry callable pointers.
#[repr(C)]
pub struct RootPendingProcessRoot {
    pub unresolved_000_887: [u32; ROOT_PENDING_SUBOBJECT_OFFSET / 4],
    pub pending_subobject: *mut RootPendingProcessSubobject,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; ROOT_PENDING_SUBOBJECT_OFFSET] =
    [0; core::mem::offset_of!(RootPendingProcessRoot, pending_subobject)];

/// The `+0x888` root sub-object prefix consumed by the virtual callback.
#[repr(C)]
pub struct RootPendingProcessSubobject {
    pub vtable: *const RootPendingProcessCallback,
}

/// root_pending_process — original: `FUN_08112bbc` @ 0x08112bbc (see the
/// module header for the raw listing, extent correction, and caller evidence).
///
/// # Safety
///
/// `root` and its `+0x888` sub-object must be live. The sub-object must name a
/// readable vtable with a callable slot `+0xf0`; the class-0x8c00 singleton
/// and its embedded timer must be valid if the slot-`+0x190` query is nonzero.
/// The firmware validates none of these pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn root_pending_process(root: *mut RootPendingProcessRoot) {
    let query = unsafe { root_slot_190_query(root.cast()) };
    let subobject = unsafe { (*root).pending_subobject };
    let callback = unsafe { (*subobject).vtable.add(ROOT_PENDING_PROCESS_SLOT).read() };
    unsafe { callback(subobject) };

    if query != 0 {
        unsafe { class_8c00_rearm_timer_post_0x11(singleton_class_8c00(), 0x1d4c0) };
    }
}
