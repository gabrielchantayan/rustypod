//! The framework's **scoped context token** — a 0x18-byte polymorphic
//! object that call sites build on the stack, hand to a service, and
//! throw away. Two of its members are ported here, both from the
//! 0x0827xxxx cluster that also holds the string/buffer class
//! (`cxx/string_object.rs`) and the resource-lookup chain
//! (`app/resource_chain.rs`):
//!
//! - [`scoped_context_construct`] — `FUN_08270394` @ 0x08270394.
//! - [`scoped_context_destroy`] — `FUN_08270414` @ 0x08270414.
//!
//! ## What the class is
//!
//! Every constructor in the family plants the same vtable literal,
//! 0x089a5b30, and lays out the same six fields:
//!
//! ```text
//! +0x00  vtable          @ always 0x089a5b30
//! +0x04  owner_valid     @ word; only its low byte is ever read
//! +0x08  owner           @ the object the token speaks for
//! +0x0c  service_context @ derived from the system root, see below
//! +0x10  registry_token  @ derived from the service context
//! +0x14  mode            @ byte
//! ```
//!
//! The family (all binary-scanned over the whole decrypted image):
//!
//! | address | `bl` | what it is |
//! |---|---|---|
//! | 0x08270394 | **109** + 2 `b` | ctor `(this, owner, mode)` — **ported here** |
//! | 0x08270414 | **175** | trivial destructor — **ported here** |
//! | 0x08270418 | 15 | field copy: `dst[+4..+0x14] = src[+4..+0x14]`, vtable untouched |
//! | 0x082703d0 | 7 | ctor that adopts another token's owner through 0x0826fd24 |
//! | 0x08270320 | 2 | a third ctor variant |
//!
//! `0x08270414` really is this class's destructor and not a generic
//! shared no-op: of its 175 call sites, 166 sit within 0x300 bytes of a
//! call to one of the constructors above, or to a function that itself
//! calls one (0x0813b898 is the archetype — it runs 0x08270394 on
//! `this`, then copies a second token in with 0x08270418, and its
//! caller at 0x080feca8 destroys the result through 0x08270414).
//!
//! ## Where the derived fields come from
//!
//! The constructor's tail calls `FUN_0826fda0` @ 0x0826fda0, which is
//! the only place the two derived words are computed:
//!
//! ```text
//! 0826fda0  cmp   r1, #0
//! 0826fda4  str   r1, [r0, #8]          @ owner (again — the ctor already wrote it)
//! 0826fda8  streq r1, [r0, #0xc]
//! 0826fdac  beq   0x826fdcc             @ no owner -> both derived words NULL
//! 0826fdb0  ldr   r1, [pc, #28]         @ &SYSTEM_ROOT (literal 0x089ca674)
//! 0826fdb4  ldr   r1, [r1]
//! 0826fdb8  ldr   r1, [r1, #0x30]       @ service context
//! 0826fdbc  str   r1, [r0, #0xc]
//! 0826fdc0  ldr   r1, [r1, #0xf60]      @ its registry
//! 0826fdc4  cmp   r1, #0
//! 0826fdc8  ldrne r1, [r1, #0x18]
//! 0826fdcc  str   r1, [r0, #0x10]
//! 0826fdd0  bx    lr
//! ```
//!
//! 0x089ca674 is a runtime-initialized RW word with 120 literal-pool
//! references across the image — the framework's system root. The
//! object at root+0x30 is what the "service context" name comes from:
//! its +0xf60 word is the registry that 0x0805e36c interrogates by
//! FourCC (`0x66696c65` = `"file"` at the call site 0x0803bf48, which is
//! also one of this constructor's callers), and +0x18 of that registry
//! is the word cached in the token.
//!
//! The class's own name does not survive in the image: none of the
//! constructors hands a literal to the class-name factory, and the
//! fifteen vtable slots at 0x089a5b30..0x089a5b68 all point into
//! undecoded code. So the port names the class for what it holds rather
//! than inventing a `TC...` name, the `cxx/string_object.rs` precedent.
//!
//! ## Deviations
//!
//! - The object and its vtable are `#[repr(C)]` structs with real Rust
//!   pointers (the `app/resource_chain.rs` precedent), so the field
//!   offsets are the original's on the 32-bit target and stay
//!   self-consistent on the 64-bit host. No literal byte offset appears
//!   in the code.
//! - The vtable is the modeled static [`SCOPED_CONTEXT_VTABLE`], which
//!   carries the fifteen ROM words verbatim; the original's literal
//!   address is [`SCOPED_CONTEXT_VTABLE_ADDRESS`]. Pointer identity with
//!   the ROM table is not preserved, exactly as in `cxx/string_object.rs`.
//! - `FUN_0826fda0` is *not* ported here (it is its own function, with
//!   its own two `bl` and one `b` call sites). It sits behind the
//!   [`CAPTURE_CONTEXT_FIELDS`] dispatch slot — the
//!   `util/context_field.rs` `CURRENT_TASK_CTX_BLOCK` pattern — whose
//!   default stub reproduces the body above exactly, reading the system
//!   root through the [`SYSTEM_ROOT`] static that stands in for the RW
//!   word @ 0x089ca674 (the `app/singletons.rs` deviation: those pages
//!   are runtime-initialized and the image holds stale bytes there).
//!   With a NULL root and a non-NULL owner the stub faults exactly where
//!   the original would with an uninitialized global; the guard is not
//!   added.
//! - [`scoped_context_destroy`] compiles to the same three-instruction
//!   frame as `runtime::cxa_guard::cxa_guard_release`, so the linker
//!   folds the two: `scoped_context_destroy` is emitted as a second
//!   global on `.text.cxa_guard_release`. Behaviorally that is exactly
//!   right — both functions are empty — but it means `objdump -d` prints
//!   only the first label, and `match.py 0x08270414 scoped_context_destroy`
//!   reports the symbol as missing. Diff it through the folded section
//!   (`match.py 0x08270414 cxa_guard_release --size 4`); the emitted code
//!   is `push {fp, lr}; mov fp, sp; pop {fp, pc}`, the crate frame around
//!   the original's bare `bx lr`, identical to `ui/noop_f7f4.rs`.
//! - The destructor's recovered C signature is `void (void)` — the body
//!   is a bare `bx lr` and consumes nothing. The port takes `this`
//!   anyway, because every one of the 175 call sites passes the token in
//!   r0 and the argument documents the calling convention; an unused
//!   AAPCS argument is ABI-identical.

use core::ptr;

/// The original's vtable literal, held in the ctor's own literal-pool
/// word @ 0x082703cc (binary-verified against osos.dec; the sibling
/// ctors' words @ 0x0827038c, 0x082703d0's @ 0x08270410 and 0x08270320's
/// hold the same value).
pub const SCOPED_CONTEXT_VTABLE_ADDRESS: usize = 0x089a_5b30;

/// The class vtable, modeled down to the fifteen words the image
/// serializes at 0x089a5b30..0x089a5b68 (the sixteenth is zero). All
/// fifteen point into undecoded code; only slot +0x08 has a known
/// consumer (`FUN_0826fd38` calls it as `this->slot8(this)`).
#[repr(C)]
pub struct ScopedContextVtable {
    /// The fifteen code pointers at 0x089a5b30..0x089a5b68.
    pub slots: [usize; 15],
}

/// The ROM vtable's contents (original @ [`SCOPED_CONTEXT_VTABLE_ADDRESS`]).
pub static SCOPED_CONTEXT_VTABLE: ScopedContextVtable = ScopedContextVtable {
    slots: [
        0x0812_9dec,
        0x0812_9b40,
        0x0820_ca2c,
        0x0812_9d28,
        0x0812_9c20,
        0x083a_0a7c,
        0x0820_bf28,
        0x0820_c2dc,
        0x0820_b88c,
        0x0820_b834,
        0x0820_c468,
        0x0820_c308,
        0x0820_c5ec,
        0x0820_ca98,
        0x083a_0aa0,
    ],
};

/// The stack token itself — 0x18 bytes on the 32-bit target.
#[repr(C)]
pub struct ScopedContext {
    /// +0x00 — the class vtable (original literal 0x089a5b30).
    pub vtable: *const ScopedContextVtable,
    /// +0x04 — cleared by every constructor. Only its low byte is read,
    /// and only by `FUN_0826fd24`, which uses it to decide whether a
    /// *source* token's owner may be adopted.
    pub owner_valid: u32,
    /// +0x08 — the object this token speaks for; NULL is the common case.
    pub owner: *mut u8,
    /// +0x0c — the system root's service context, or NULL when there is
    /// no owner.
    pub service_context: *mut u8,
    /// +0x10 — the service registry's cached word, or NULL.
    pub registry_token: *mut u8,
    /// +0x14 — the caller's mode byte, written last.
    pub mode: u8,
}

/// Pointer-slot index of the service context inside the system root
/// (the original's `ldr r1, [r1, #0x30]`). Expressed as an index rather
/// than a byte offset so it addresses the same slot on the target, where
/// a pointer is 4 bytes, and on the host, where it is 8.
const ROOT_SERVICE_CONTEXT_SLOT: usize = 0x30 / 4;

/// Pointer-slot index of the registry inside the service context
/// (`ldr r1, [r1, #0xf60]`).
const SERVICE_CONTEXT_REGISTRY_SLOT: usize = 0xf60 / 4;

/// Pointer-slot index of the cached word inside the registry
/// (`ldrne r1, [r1, #0x18]`).
const REGISTRY_TOKEN_SLOT: usize = 0x18 / 4;

/// Stands in for the runtime-initialized RW word @ 0x089ca674 — the
/// framework's system root, from which the constructor's callee derives
/// both of the token's context fields. Defaults to NULL, which is the
/// pre-init state; wire it before any owner-bearing token is built.
pub static mut SYSTEM_ROOT: *const *mut u8 = ptr::null();

/// Default [`CAPTURE_CONTEXT_FIELDS`] stub: `FUN_0826fda0` @ 0x0826fda0,
/// reproduced instruction for instruction (see the module header). With
/// no owner both derived words are cleared and the system root is never
/// read; with an owner the root is walked unguarded, exactly as the
/// original does.
unsafe extern "C" fn capture_context_fields_stub(token: *mut ScopedContext, owner: *mut u8) {
    (*token).owner = owner;
    if owner.is_null() {
        (*token).service_context = ptr::null_mut();
        (*token).registry_token = ptr::null_mut();
        return;
    }

    let root = ptr::read_volatile(ptr::addr_of!(SYSTEM_ROOT)).read();
    let service_context = (root as *const *mut u8).add(ROOT_SERVICE_CONTEXT_SLOT).read();
    (*token).service_context = service_context;

    let registry = (service_context as *const *mut u8)
        .add(SERVICE_CONTEXT_REGISTRY_SLOT)
        .read();
    (*token).registry_token = if registry.is_null() {
        ptr::null_mut()
    } else {
        (registry as *const *mut u8).add(REGISTRY_TOKEN_SLOT).read()
    };
}

/// Indirect dispatch for the context-capture callee `FUN_0826fda0` @
/// 0x0826fda0 (the `util/context_field.rs` `CURRENT_TASK_CTX_BLOCK`
/// pattern). That function is not ported — it is a separate function
/// with its own call sites — so the slot's default stub models it
/// exactly and host tests install a recording mock.
pub static mut CAPTURE_CONTEXT_FIELDS: unsafe extern "C" fn(*mut ScopedContext, *mut u8) =
    capture_context_fields_stub;

/// scoped_context_construct — original: `FUN_08270394` @ 0x08270394
/// (60 bytes: 56 code + the 4-byte vtable literal @ 0x082703cc, which
/// Ghidra's 56-byte extent drops; **109 `bl` + 2 `b` call sites**,
/// binary-scanned over the whole decrypted image).
///
/// ```text
/// 08270394  mov   r3, r0
/// 08270398  ldr   r0, [0x082703cc]   @ 0x089a5b30, the class vtable
/// 0827039c  push  {lr}
/// 082703a0  str   r0, [r3]
/// 082703a4  mov   r0, #0
/// 082703a8  stmib r3, {r0, r1}       @ +0x04 = 0, +0x08 = owner
/// 082703ac  str   r0, [r3, #0xc]
/// 082703b0  str   r0, [r3, #0x10]
/// 082703b4  strb  r0, [r3, #0x14]
/// 082703b8  mov   r0, r3
/// 082703bc  bl    0x0826fda0         @ r1 is still the owner
/// 082703c0  mov   r0, r3
/// 082703c4  strb  r2, [r3, #0x14]
/// 082703c8  pop   {pc}
/// ```
///
/// Two orderings are load-bearing and are reproduced: the mode byte is
/// zeroed *before* the capture callee runs and written *after* it, so a
/// callee that reads +0x14 sees zero; and the owner is stored twice,
/// once by the `stmib` and once by the callee, which matters only if the
/// two ever disagree. Returns `this`, which is what the two tail-`b`
/// call sites (0x08159a6c, 0x0816ef78) forward to their own callers.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scoped_context_construct(
    this: *mut ScopedContext,
    owner: *mut u8,
    mode: u8,
) -> *mut ScopedContext {
    (*this).vtable = &SCOPED_CONTEXT_VTABLE;
    (*this).owner_valid = 0;
    (*this).owner = owner;
    (*this).service_context = ptr::null_mut();
    (*this).registry_token = ptr::null_mut();
    (*this).mode = 0;

    // Volatile slot read — the util/inner_state.rs rationale: the slot
    // exists to be swapped at runtime, so the default must not be
    // constant-folded in.
    ptr::read_volatile(ptr::addr_of!(CAPTURE_CONTEXT_FIELDS))(this, owner);

    (*this).mode = mode;
    this
}

/// scoped_context_destroy — original: `FUN_08270414` @ 0x08270414
/// (4 bytes; **175 `bl` call sites**, binary-scanned — no `b` sites).
///
/// The whole body is `bx lr`. The class owns nothing: its two derived
/// words are borrowed views onto the system root, and its owner is not
/// retained, so destruction has nothing to release. The token is left
/// exactly as the constructor wrote it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn scoped_context_destroy(_this: *mut ScopedContext) {}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    /// Serializes every test that swaps [`CAPTURE_CONTEXT_FIELDS`] or
    /// [`SYSTEM_ROOT`] (the `util/context_field.rs` `SLOT_TEST_LOCK`
    /// precedent).
    static SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut MOCK_CALLS: u32 = 0;
    static mut MOCK_OWNER: *mut u8 = ptr::null_mut();
    static mut MOCK_MODE_AT_CALL: u8 = 0xff;
    static mut MOCK_TOKEN: *mut ScopedContext = ptr::null_mut();

    unsafe extern "C" fn recording_capture(token: *mut ScopedContext, owner: *mut u8) {
        MOCK_CALLS += 1;
        MOCK_TOKEN = token;
        MOCK_OWNER = owner;
        MOCK_MODE_AT_CALL = (*token).mode;
    }

    /// Restores the default stub and a NULL root on drop, even on panic.
    struct SlotGuard;
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(CAPTURE_CONTEXT_FIELDS).write_volatile(capture_context_fields_stub);
                ptr::addr_of_mut!(SYSTEM_ROOT).write_volatile(ptr::null());
            }
        }
    }

    /// A token pre-filled with sentinels, so every field the constructor
    /// is supposed to write is observably overwritten.
    fn poisoned_token() -> ScopedContext {
        ScopedContext {
            vtable: usize::MAX as *const ScopedContextVtable,
            owner_valid: 0xdead_beef,
            owner: usize::MAX as *mut u8,
            service_context: usize::MAX as *mut u8,
            registry_token: usize::MAX as *mut u8,
            mode: 0x5a,
        }
    }

    unsafe fn install_mock() {
        MOCK_CALLS = 0;
        MOCK_TOKEN = ptr::null_mut();
        MOCK_OWNER = usize::MAX as *mut u8;
        MOCK_MODE_AT_CALL = 0xff;
        ptr::addr_of_mut!(CAPTURE_CONTEXT_FIELDS).write_volatile(recording_capture);
    }

    #[test]
    fn writes_every_field_and_returns_this() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut token = poisoned_token();
        let owner = 0x1234_5678usize as *mut u8;
        unsafe { install_mock() };

        let returned = unsafe { scoped_context_construct(&mut token, owner, 0x2a) };

        assert_eq!(returned, &mut token as *mut ScopedContext);
        assert_eq!(token.vtable, &SCOPED_CONTEXT_VTABLE as *const ScopedContextVtable);
        assert_eq!(token.owner_valid, 0);
        assert_eq!(token.owner, owner);
        assert!(token.service_context.is_null());
        assert!(token.registry_token.is_null());
        assert_eq!(token.mode, 0x2a);
    }

    #[test]
    fn calls_the_capture_callee_once_with_the_owner_and_a_zero_mode() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut token = poisoned_token();
        let owner = 0xabc0_0000usize as *mut u8;
        unsafe { install_mock() };

        unsafe { scoped_context_construct(&mut token, owner, 0xff) };

        // Copy the recorded values out through raw pointers: taking a
        // reference to a `static mut` in `assert_eq!` is the pattern the
        // 2024 edition rejects.
        let (calls, seen_token, seen_owner, mode_at_call) = unsafe {
            (
                ptr::addr_of!(MOCK_CALLS).read(),
                ptr::addr_of!(MOCK_TOKEN).read(),
                ptr::addr_of!(MOCK_OWNER).read(),
                ptr::addr_of!(MOCK_MODE_AT_CALL).read(),
            )
        };
        assert_eq!(calls, 1, "exactly one capture call");
        assert_eq!(seen_token, &mut token as *mut ScopedContext);
        assert_eq!(seen_owner, owner);
        assert_eq!(mode_at_call, 0, "mode is written after the callee");
    }

    #[test]
    fn mode_round_trips_edge_values() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        unsafe { install_mock() };
        for mode in [0u8, 1, 0x7f, 0x80, 0xff] {
            let mut token = poisoned_token();
            unsafe { scoped_context_construct(&mut token, ptr::null_mut(), mode) };
            assert_eq!(token.mode, mode);
        }
    }

    /// The registry fixture: a slot array whose [`REGISTRY_TOKEN_SLOT`]
    /// holds the word the token should end up caching.
    fn registry_with_token(token_word: *mut u8) -> Vec<*mut u8> {
        let mut registry = vec![ptr::null_mut(); REGISTRY_TOKEN_SLOT + 1];
        registry[REGISTRY_TOKEN_SLOT] = token_word;
        registry
    }

    #[test]
    fn default_stub_leaves_both_derived_words_null_without_an_owner() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut token = poisoned_token();
        // The root stays NULL: with no owner the stub must never read it.
        unsafe { scoped_context_construct(&mut token, ptr::null_mut(), 3) };

        assert!(token.owner.is_null());
        assert!(token.service_context.is_null());
        assert!(token.registry_token.is_null());
        assert_eq!(token.mode, 3);
    }

    #[test]
    fn default_stub_walks_the_system_root_for_an_owner() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;

        let mut registry = registry_with_token(0x4242_4242usize as *mut u8);
        let mut service_context: Vec<*mut u8> = vec![ptr::null_mut(); SERVICE_CONTEXT_REGISTRY_SLOT + 1];
        service_context[SERVICE_CONTEXT_REGISTRY_SLOT] = registry.as_mut_ptr() as *mut u8;
        let mut root: Vec<*mut u8> = vec![ptr::null_mut(); ROOT_SERVICE_CONTEXT_SLOT + 1];
        root[ROOT_SERVICE_CONTEXT_SLOT] = service_context.as_mut_ptr() as *mut u8;
        let root_word = Box::new(root.as_mut_ptr() as *mut u8);

        unsafe {
            ptr::addr_of_mut!(SYSTEM_ROOT).write_volatile(&*root_word as *const *mut u8);
        }

        let mut token = poisoned_token();
        let owner = 0x0011_2233usize as *mut u8;
        unsafe { scoped_context_construct(&mut token, owner, 1) };

        assert_eq!(token.owner, owner);
        assert_eq!(token.service_context, service_context.as_mut_ptr() as *mut u8);
        assert_eq!(token.registry_token, 0x4242_4242usize as *mut u8);
    }

    #[test]
    fn default_stub_yields_a_null_token_when_the_registry_slot_is_null() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;

        let mut service_context: Vec<*mut u8> = vec![ptr::null_mut(); SERVICE_CONTEXT_REGISTRY_SLOT + 1];
        let mut root: Vec<*mut u8> = vec![ptr::null_mut(); ROOT_SERVICE_CONTEXT_SLOT + 1];
        root[ROOT_SERVICE_CONTEXT_SLOT] = service_context.as_mut_ptr() as *mut u8;
        let root_word = Box::new(root.as_mut_ptr() as *mut u8);

        unsafe {
            ptr::addr_of_mut!(SYSTEM_ROOT).write_volatile(&*root_word as *const *mut u8);
        }

        let mut token = poisoned_token();
        unsafe { scoped_context_construct(&mut token, 1 as *mut u8, 0) };

        assert_eq!(token.service_context, service_context.as_mut_ptr() as *mut u8);
        assert!(
            token.registry_token.is_null(),
            "a NULL registry must leave the cached word NULL, not fault"
        );
    }

    #[test]
    fn destroy_touches_nothing() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut token = poisoned_token();
        unsafe { install_mock() };
        unsafe { scoped_context_construct(&mut token, 0x99 as *mut u8, 0x11) };
        let before = (
            token.vtable,
            token.owner_valid,
            token.owner,
            token.service_context,
            token.registry_token,
            token.mode,
        );

        scoped_context_destroy(&mut token);

        assert_eq!(
            (
                token.vtable,
                token.owner_valid,
                token.owner,
                token.service_context,
                token.registry_token,
                token.mode,
            ),
            before
        );
    }

    #[test]
    fn destroy_accepts_a_null_token() {
        // The original never dereferences `this`; neither may the port.
        scoped_context_destroy(ptr::null_mut());
    }

    #[test]
    fn vtable_holds_the_rom_words() {
        assert_eq!(SCOPED_CONTEXT_VTABLE.slots[0], 0x0812_9dec);
        assert_eq!(SCOPED_CONTEXT_VTABLE.slots[2], 0x0820_ca2c);
        assert_eq!(SCOPED_CONTEXT_VTABLE.slots[14], 0x083a_0aa0);
        assert_eq!(SCOPED_CONTEXT_VTABLE_ADDRESS, 0x089a_5b30);
    }
}
