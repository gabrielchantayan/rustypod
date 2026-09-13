//! Scoped path-component query wrapper.
//!
//! Port: [`path_component_query`] — original: `FUN_0809b678` @
//! **0x0809b678** (48 bytes; **12 plain `bl` call sites, 0 predicated
//! `bl`, 0 `b`**, binary-scanned by decoding every ARM branch in
//! `osos.dec`).
//!
//! ## Algorithm
//!
//! Builds a two-word derived [`StringObject`] path object in its r2/r3
//! stack spill slots, calls [`path_component_query_worker`], destroys the
//! storage through `string_object_destroy_veneer`, then returns the helper
//! status unchanged. Raw ARM:
//!
//! ```text
//! 0809b678  stmdb sp!, {r2,r3,r4,lr}
//! 0809b67c  mov   r4,r1
//! 0809b680  mov   r1,r0
//! 0809b684  mov   r0,sp
//! 0809b688  bl    0x08279284  @ path_object_construct
//! 0809b68c  mov   r1,r4
//! 0809b690  bl    0x0809b6a8  @ component-query helper
//! 0809b694  mov   r4,r0
//! 0809b698  mov   r0,sp
//! 0809b69c  bl    0x082792fc  @ string_object_destroy_veneer
//! 0809b6a0  mov   r0,r4
//! 0809b6a4  ldmia sp!, {r2,r3,r4,pc}
//! ```
//!
//! All twelve callers pass a path C string and zero as the second word;
//! callers branch on its status, with several distinguishing 0 and 13 for
//! setup/error paths. [`path_component_query_worker`] preserves the exact
//! scoped guard/facade/query sequence, with the unresolved facade operation
//! at 0x08149e38 isolated as its own device boundary.

use core::mem::MaybeUninit;

use crate::app::path_component_query_worker::path_component_query_worker;
use crate::app::path_object_construct::path_object_construct;
use crate::cxx::string_object::{string_object_destroy_veneer, StringObject};


/// `path_component_query` — original: `FUN_0809b678` @ **0x0809b678**
/// (48 bytes; **12 plain `bl` call sites, 0 predicated, 0 tail branches**).
///
/// Constructs a derived path object from `path`, runs the ported
/// [`path_component_query_worker`] with `base_hint` as its guard base hint,
/// destroys the stack storage, and returns the helper status verbatim.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_component_query(path: *const u8, base_hint: u32) -> u32 {
    let mut guard = MaybeUninit::<StringObject>::uninit();
    let guard = guard.as_mut_ptr();
    let path_object = path_object_construct(guard, path);
    let status = path_component_query_worker(path_object, base_hint);
    string_object_destroy_veneer(guard);
    status
}

