//! The media-player command facade and its function-local-static
//! accessor.
//!
//! Port:
//! - [`media_command_facade_get`] — original: `FUN_08189464` @
//!   0x08189464 (72 bytes of code plus a 5-word constant pool = 92
//!   bytes; **76 `bl` call sites from 22 distinct callers**).
//!
//! ## What the object is
//!
//! The fixed object at 0x08a107f8 is a thin **facade over the media
//! player**: a command arrives as a message, the dispatcher fetches
//! this object, and a one-line method on it marks the object dirty and
//! forwards the command to the player's vtable. Its constructor
//! `FUN_0818a010` (binary-verified, 84 bytes) lays it out as
//!
//! ```text
//! +0x00  the TPodMediaPlayer singleton   (bl 0x0817ceb4 = media_player_get)
//! +0x04  the registry class-0x6600 object (bl 0x08100b74 = instance_of_class_6600)
//! +0x08  byte  0
//! +0x09  byte  0
//! +0x0a  half  0
//! +0x0c  byte  0
//! +0x0d  byte  0      "a command was issued" flag - every method sets it to 1
//! +0x10  word -1
//! +0x14  word -1
//! +0x18  word -1
//! +0x1c  word  0
//! +0x20  word  0xffff63c0   (-40000; pool literal @ 0x0818a064)
//! ```
//!
//! +0x20 is the last field written, so [`MEDIA_COMMAND_SIZE`] = 0x24 is
//! the constructor's exact extent. Unlike the `app/singletons.rs`
//! family there is no `operator_new` here to confirm a size
//! independently — the object is statically allocated.
//!
//! The facade's methods live immediately around the accessor and all
//! have the same one-line shape, e.g. `FUN_081892e8`:
//! `ldr r0, [r0]; ldr r1, [r0]; ldr r1, [r1, #0x88]; bx r1` — load the
//! player from +0x00 and tail-dispatch through its vtable (slots +0x58,
//! +0x68, +0x78, +0x88, +0x120, +0x130, +0x158, +0x17c, +0x1a4
//! observed), most of them after `strb #1, [r0, #0xd]`.
//!
//! Who calls it: 21 of the 76 sites are in the message pump
//! `FUN_08100bb4`, whose switch keys are the class-0x6600 command codes
//! `0x6600000d`, `0x6600000e`, `0x6600000f`, … — each case fetches this
//! facade and calls one method on it. The rest are the small command
//! wrappers in the 0x082c6a40..0x082c6ed0 cluster.
//!
//! ## The accessor
//!
//! `FUN_08189464` is a textbook ADS function-local static, the same
//! idiom as `app/node_list.rs`'s `node_list_get` and not the
//! `operator_new` cache pattern of `app/singletons.rs`:
//!
//! ```text
//! ldr r0, =0x089ca3a4      ; pool @ 0x081894ac
//! ldr r0, [r0, #0xc]       ; ...+0xc IS the guard word @ 0x089ca3b0
//! tst r0, #1
//! bne done                 ; inlined fast path: bit 0 = initialized
//! ldr r0, =0x089ca3b0      ; pool @ 0x081894b0: the guard, again
//! bl  cxa_guard_acquire    ; 0x082ab31c (ported)
//! cmp r0, #0; beq done
//! ldr r0, =0x08a107f8      ; pool @ 0x081894b4: the object
//! bl  0x0818a010           ; the constructor, returns `this` in r0
//! ldr r2, =0x089ca09c      ; pool @ 0x081894b8: __dso_handle
//! ldr r1, =0x0817f190      ; pool @ 0x081894bc: the "destructor"
//! bl  cxa_atexit           ; 0x082ab1c8 (ported)
//! bl  cxa_guard_release    ; 0x082ab338 (ported)
//! done:
//! ldr r0, =0x08a107f8      ; reloaded - NOT the ctor's return
//! ```
//!
//! Ghidra reports the extent as 72 bytes, the code only. The five pool
//! words at 0x081894ac..0x081894bc belong to the function; the next
//! function starts at 0x081894c0 (`ldr r0, [r0]; ldr r1, [r0]; ldr r1,
//! [r1, #0x158]; bx r1`, another facade method), so the true extent is
//! 0x08189464..0x081894c0 = 92 bytes.
//!
//! The guard pair and `cxa_atexit` are ported and called directly. The
//! constructor is not, so it rides the [`MEDIA_COMMAND_CTOR`] seam —
//! which is why this symbol is **not hook-ready**: the documented
//! zeroing default installs neither the player pointer at +0x00 nor the
//! three `-1` sentinels, so stock code branched here would dispatch
//! through a NULL player.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// The constructor's exact extent: it writes fields up to and including
/// the word at +0x20.
pub const MEDIA_COMMAND_SIZE: usize = 0x24;

/// `__dso_handle` — the pool word @ 0x081894b8 (0x089ca09c), the key
/// every ADS static's `cxa_atexit` registration carries.
const DSO_HANDLE: i32 = 0x089ca09c;

/// The one-time-initialization guard (original: the word @ 0x089ca3b0,
/// read on the fast path as `[0x089ca3a4 + 0xc]`).
///
/// A crate static rather than the .bss word: the 0x089cxxxx pages are
/// runtime-initialized and the decrypted image holds stale UI strings
/// there (the `block_mgr.rs` deviation). Zero is the exact pre-init
/// state either way.
pub static mut MEDIA_COMMAND_GUARD: u32 = 0;

/// The facade object itself (original: the fixed object @ 0x08a107f8,
/// the pool word @ 0x081894b4). Same crate-static deviation as the
/// guard; zero-init is the pre-construction state.
pub static mut MEDIA_COMMAND_FACADE: [u8; MEDIA_COMMAND_SIZE] = [0; MEDIA_COMMAND_SIZE];

/// An ADS C++ constructor: takes the storage, returns `this`.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// The default stub for the unported constructor `FUN_0818a010`:
/// zeroes the object and returns it.
///
/// A faithful *subset* — the original zeroes +0x08..+0x0d and +0x1c —
/// but it installs neither singleton pointer nor the `-1`/0xffff63c0
/// fields, which is why the module header calls this symbol not
/// hook-ready. Volatile stores: a plain loop is rewritten by LLVM into
/// a call to `__aeabi_memclr`, which does not exist in this build.
unsafe extern "C" fn zeroing_media_command_ctor(this: *mut u8) -> *mut u8 {
    for offset in 0..MEDIA_COMMAND_SIZE {
        this.add(offset).write_volatile(0);
    }
    this
}

/// The active constructor — the dispatch seam for `FUN_0818a010`
/// (`bl` @ 0x0818948c). Host tests install a recording mock; the real
/// port replaces the default when it exists.
pub static mut MEDIA_COMMAND_CTOR: Constructor = zeroing_media_command_ctor;

/// The destructor registered with `cxa_atexit` — original: the pool
/// word @ 0x081894bc, 0x0817f190.
///
/// That address is **not a function entry**: it sits 0xbc bytes inside
/// `FUN_0817f0d4` (0x0817f0d4, 228 bytes), on a `ldr r2, [pc, #36]`
/// that falls through to a `pop {r0-r8, pc}` — run as a shutdown
/// handler it would pop a frame it never pushed, so the registration
/// could never fire. retailOS never runs `exit`'s chain anyway
/// (`runtime/shutdown_chain.rs`: the sole runner caller is
/// `exit_stdio_cleanup`). The same situation as `node_list_get`'s
/// 0x0810516c. A no-op matches every observable path.
unsafe extern "C" fn media_command_destructor(_object: *mut c_void) {}

/// media_command_facade_get — original: `FUN_08189464` @ 0x08189464
/// (92 bytes: 72 of code plus a 5-word pool; 76 `bl` call sites from 22
/// distinct callers, and no plain-`b` tail sites — verified by decoding
/// every B/BL word in osos.dec).
///
/// Returns the media-player command facade, running its one-time
/// construction on the first call. See the module header for the
/// object layout, the callers, and the stock instruction sequence.
///
/// Faithful details:
/// - The return value is the object's address *reloaded* after the init
///   block (the original's second `ldr r0, [0x81894b4]`), never the
///   constructor's return.
/// - The fast path tests bit 0 only (`tst r0, #1`) while
///   [`cxa_guard_acquire`] tests the whole word, so a nonzero guard
///   with bit 0 clear — a state this pair never produces — takes the
///   slow path and is still turned away.
/// - A refused acquire (a re-entrant initializer) skips construction
///   and still hands out the object half-built; the guard is spent
///   either way.
/// - The `cxa_atexit` registration carries the *constructor's* return,
///   not the object literal. They coincide here, and the distinction is
///   preserved.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_command_facade_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(MEDIA_COMMAND_GUARD);
    let object = core::ptr::addr_of_mut!(MEDIA_COMMAND_FACADE) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_COMMAND_CTOR))(object);
        cxa_atexit(this as *mut c_void, media_command_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test below: the guard, the object, the ctor
    /// slot and the shutdown chain are all process-wide.
    static FACADE_LOCK: Mutex<()> = Mutex::new(());

    /// Storage handed to the constructor, in order.
    static mut CTOR_BLOCKS: Vec<*mut u8> = Vec::new();

    /// What the recording constructor returns.
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
        this.write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    /// Box-backed node allocator pair for the shutdown chain (the
    /// shipped defaults are the firmware malloc/free, wrong for host
    /// memory — the node_list.rs test pattern).
    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: media_command_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(MEDIA_COMMAND_FACADE) as *mut u8
    }

    /// Resets the guard, the object and the chain to their pre-init
    /// state and installs the Box allocator pair.
    fn reset() -> MutexGuard<'static, ()> {
        let guard = FACADE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            MEDIA_COMMAND_GUARD = 0;
            for offset in 0..MEDIA_COMMAND_SIZE {
                storage().add(offset).write(0xa5);
            }
            MEDIA_COMMAND_CTOR = zeroing_media_command_ctor;
            CTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held.
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            // Drain leftover registrations BEFORE restoring the
            // firmware allocator pair, so the nodes are freed by the
            // allocator that made them.
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            MEDIA_COMMAND_CTOR = zeroing_media_command_ctor;
            MEDIA_COMMAND_GUARD = 0;
        }
        drop(guard);
    }

    #[test]
    fn the_first_call_constructs_registers_and_publishes_the_guard() {
        let guard = reset();
        unsafe {
            MEDIA_COMMAND_CTOR = recording_ctor;
            assert_eq!(media_command_facade_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![storage()], "constructed in place");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(MEDIA_COMMAND_GUARD)),
                1,
                "acquire published the flag"
            );

            let head = *shutdown_chain_head();
            assert!(!head.is_null(), "registered with cxa_atexit");
            assert_eq!((*head).arg as *mut u8, storage(), "the ctor's return");
            assert_eq!((*head).handler as usize, media_command_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE, "__dso_handle @ 0x089ca09c");
            assert!((*head).next.is_null(), "registered exactly once");
        }
        restore(guard);
    }

    #[test]
    fn the_second_call_takes_the_bit0_fast_path() {
        let guard = reset();
        unsafe {
            MEDIA_COMMAND_CTOR = recording_ctor;
            media_command_facade_get();
            // A post-construction mutation must survive: the 76 call
            // sites after boot must not reconstruct the facade.
            storage().add(0x0d).write(1);
            assert_eq!(media_command_facade_get(), storage());
            assert_eq!(media_command_facade_get(), storage());
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
            assert_eq!(storage().add(0x0d).read(), 1, "no reconstruction");
            assert!((*(*shutdown_chain_head())).next.is_null(), "no second registration");
        }
        restore(guard);
    }

    #[test]
    fn a_guard_with_bit0_set_short_circuits_everything() {
        let guard = reset();
        unsafe {
            MEDIA_COMMAND_CTOR = recording_ctor;
            MEDIA_COMMAND_GUARD = 3; // bit 0 set -> `tst r0, #1`, bne done
            assert_eq!(media_command_facade_get(), storage());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty(), "no construction");
            assert!(shutdown_chain_head().read().is_null(), "no registration");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(MEDIA_COMMAND_GUARD)), 3, "untouched");
            assert_eq!(storage().read(), 0xa5, "the object is handed out untouched");
        }
        restore(guard);
    }

    #[test]
    fn a_nonzero_guard_with_bit0_clear_is_still_turned_away_by_acquire() {
        // The fast path tests bit 0, cxa_guard_acquire the whole word.
        // This pair never produces the state, but the original's
        // two-level test defines its behavior.
        let guard = reset();
        unsafe {
            MEDIA_COMMAND_CTOR = recording_ctor;
            MEDIA_COMMAND_GUARD = 2;
            assert_eq!(media_command_facade_get(), storage());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty(), "acquire refused: no construction");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(MEDIA_COMMAND_GUARD)),
                2,
                "a refused acquire never writes"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_object_literal_is_returned_not_the_constructors_value() {
        // The original reloads the pool word 0x081894b4; only the
        // REGISTRATION sees the constructor's return.
        let guard = reset();
        unsafe {
            MEDIA_COMMAND_CTOR = recording_ctor;
            CTOR_RESULT = storage().add(8); // deliberately different
            assert_eq!(media_command_facade_get(), storage(), "the reloaded literal wins");
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(8));
        }
        restore(guard);
    }

    #[test]
    fn the_registration_is_real_and_the_chain_runs_the_noop_destructor() {
        let guard = reset();
        unsafe {
            media_command_facade_get();
            storage().add(0x0d).write(0xa5);
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null(), "the node ran and was freed");
            assert_eq!(storage().add(0x0d).read(), 0xa5, "the no-op destructor touched nothing");
        }
        restore(guard);
    }

    #[test]
    fn the_default_stub_zeroes_exactly_the_constructors_extent() {
        let guard = reset();
        unsafe {
            assert_eq!(media_command_facade_get(), storage());
            assert!(
                (0..MEDIA_COMMAND_SIZE).all(|offset| storage().add(offset).read() == 0),
                "the documented zeroing default"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_object_extent_is_the_constructors_last_field_plus_one_word() {
        // `str r0, [r4, #32]` @ 0x0818a048 is the final store.
        assert_eq!(MEDIA_COMMAND_SIZE, 0x24);
        assert_eq!(DSO_HANDLE, 0x089ca09c);
    }
}
