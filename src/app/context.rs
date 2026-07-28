//! `context_target_id` — original: `FUN_0813b6f4` @ 0x0813b6f4
//! (12 bytes; **254 `bl` call sites**, binary-scanned — one of the
//! hottest functions in the mid region).
//!
//! ```text
//! ldr r0, =0x089cc7ec ; ldr r0, [r0, #8] ; bx lr
//! ```
//!
//! The literal is the base of a small global **application context**
//! object; this reads its word at +8. What that word is, recovered from
//! the callers:
//!
//! - It is a numeric **class/resource id**, not a pointer, and 0 means
//!   "none". Its one writer, `FUN_082028d4` @ 0x08202904, stores the
//!   literal 0x7a88 (which also appears in the id table @ 0x083f61b0,
//!   next to the "None" literal, alongside 0x7d80) right after raising
//!   the global flag byte @ 0x089d0074.
//! - Every reader has the same shape — 127 distinct callers, most of
//!   them view classes in the 0x0839xxxx..0x083bxxxx block:
//!   ```c
//!   id = context_target_id();
//!   if (id != 0) {
//!       manager = /* the object registry */;
//!       target  = manager->vtable[0xe8](manager, id);   // lookup by id
//!       if (target) { ... }
//!   }
//!   ```
//!   i.e. the field names a pending target to resolve through the
//!   registry (`FUN_081883fc` fetches the manager for the sibling id
//!   0x8080; `FUN_081d2184` is the by-id registry lookup).
//!
//! The rest of the context object, from the code that shares the same
//! literal:
//!
//! ```text
//! +0x00  (unread by anything ported here)
//! +0x04  trace nesting depth — incremented @ 0x08134af8 after building
//!        a "controller_..." event string, decremented @ 0x081e9e4c
//!        which asserts (`bl 0x08030f44`) if it goes negative, and
//!        tested != 0 @ 0x08134674 to gate the event emit
//! +0x08  the target id this getter returns; written @ 0x0813b704
//! +0x0c  referenced @ 0x0829b088 (as 0x089cc7f8)
//! ```
//!
//! Deviation (the block_mgr.rs / types.rs precedent): the object is
//! modeled as the crate static [`APP_CONTEXT`] instead of living at
//! 0x089cc7ec. That page is runtime-initialized RW data — the decrypted
//! image holds stale UI strings there ("how_Info_Template_CenteredText"
//! at 0x089cc7ec), so the image bytes carry no information. The static
//! defaults to all-zero, exactly the pre-init state, so the getter
//! returns 0 ("no target") until something stores an id. Every field is
//! a 32-bit word, so the target layout holds on a 64-bit host too
//! (asserted below).

/// The global application context object (original: the 0x089cc7ec
/// literal shared by 0x0813b6f4, 0x0813b704, 0x08134674, 0x08134af8,
/// 0x081e9e4c, 0x0829b084 and 0x082ae514).
#[repr(C)]
pub struct AppContext {
    /// +0x00: not touched by any ported reader.
    pub reserved0: u32,
    /// +0x04: trace-event nesting depth (see the module header).
    pub trace_depth: i32,
    /// +0x08: pending target id — 0 means "none".
    pub target_id: u32,
    /// +0x0c: referenced as 0x089cc7f8 @ 0x0829b088.
    pub reserved3: u32,
}

// Target-exact layout (all-u32, so it also holds on a 64-bit host).
const _: [u8; 0x04] = [0; core::mem::offset_of!(AppContext, trace_depth)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(AppContext, target_id)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(AppContext, reserved3)];

/// The context object itself (see the module-header deviation). Zeroed
/// until the framework initializes it.
pub static mut APP_CONTEXT: AppContext =
    AppContext { reserved0: 0, trace_depth: 0, target_id: 0, reserved3: 0 };

/// context_target_id — original: `FUN_0813b6f4` @ 0x0813b6f4
/// (12 bytes).
///
/// Returns the global context's pending target id; 0 means there is no
/// target, and every caller checks for that before resolving it.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_target_id() -> u32 {
    // Volatile: the word is written at runtime (by 0x08202904 on
    // device, by tests here), and a build in which nothing writes it
    // must not constant-fold the zero in.
    core::ptr::read_volatile(core::ptr::addr_of!(APP_CONTEXT.target_id))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes the tests that mutate the global context.
    static CONTEXT_LOCK: Mutex<()> = Mutex::new(());

    /// Installs `id` and hands back the guard; the caller restores.
    fn with_target_id(id: u32) -> MutexGuard<'static, ()> {
        let guard = CONTEXT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { APP_CONTEXT.target_id = id };
        guard
    }

    /// Restores the zeroed default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { APP_CONTEXT.target_id = 0 };
        drop(guard);
    }

    #[test]
    fn the_default_state_is_no_target() {
        let guard = with_target_id(0);
        assert_eq!(unsafe { context_target_id() }, 0);
        restore(guard);
    }

    #[test]
    fn it_returns_the_id_the_writer_stored() {
        // 0x7a88 is the literal the one writer @ 0x08202904 stores.
        let guard = with_target_id(0x7a88);
        assert_eq!(unsafe { context_target_id() }, 0x7a88);
        restore(guard);
    }

    #[test]
    fn the_full_word_survives_the_round_trip() {
        let guard = with_target_id(0xffff_ffff);
        assert_eq!(unsafe { context_target_id() }, 0xffff_ffff);
        restore(guard);
    }

    #[test]
    fn the_neighbouring_fields_are_not_what_is_read() {
        let guard = with_target_id(0x1234);
        unsafe {
            APP_CONTEXT.reserved0 = 0xaaaa_aaaa;
            APP_CONTEXT.trace_depth = -1;
            APP_CONTEXT.reserved3 = 0xbbbb_bbbb;
            assert_eq!(context_target_id(), 0x1234, "only +8 is loaded");
            APP_CONTEXT.reserved0 = 0;
            APP_CONTEXT.trace_depth = 0;
            APP_CONTEXT.reserved3 = 0;
        }
        restore(guard);
    }
}
