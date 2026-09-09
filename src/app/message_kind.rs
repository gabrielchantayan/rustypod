//! `message_kind_construct` — original: `FUN_08266a48` @ 0x08266a48
//! (24 bytes of code, 0x08266a48..0x08266a60, plus the 4-byte literal-pool
//! word @ 0x08266a60 holding the vtable address, so 28 bytes of true
//! extent; **45 `bl` and 0 `b` call sites** in `decomp/osos.asm`).
//!
//! The base constructor of the framework's kind-tagged **message** class —
//! the class every task-queue message envelope descends from.
//!
//! ```text
//! 08266a48  push {r4, lr}
//! 08266a4c  mov  r4, r1            @ kind
//! 08266a50  bl   0x08275bb8        @ framework_object_construct(this)
//! 08266a54  ldr  r1, [pc, #4]      @ = 0x089a3788 (pool word @ 0x08266a60)
//! 08266a58  stmia r0, {r1, r4}     @ this->vtable = VTABLE; this->kind = kind
//! 08266a5c  pop  {r4, pc}
//! 08266a60  .word 0x089a3788
//! ```
//!
//! # What the class is
//!
//! The object is eight bytes: the [`FrameworkObject`] root subobject at
//! +0x00 (whose vtable this constructor overwrites, exactly like every
//! other derived constructor in the hierarchy) and the caller's `kind` tag
//! at +0x04. The constructor is not an allocator: every one of the 45 call
//! sites passes storage it has already obtained — arena memory from
//! `FUN_0826c0d8(..., 8)`/`(..., 0xc)`, an `operator_new` block
//! (e.g. `FUN_08266aa4(8)`), or a stack frame slot — and immediately
//! overwrites the vtable again with its own derived literal, keeping only
//! the +0x04 kind store. Observed `kind` immediates at the call sites:
//! `0` (four sites), `1`, `2`, `3`, `4` (the `0x08157xxx` family), `0x16`
//! (the queued-message envelopes `app/queued_message.rs`), `0x17`, `0x22`,
//! `0x28`, `0x20003`, plus several `DAT`-loaded tags — i.e. `kind` is the
//! message class/queue tag, matching how `queued_message_construct` treats
//! its fixed `0x16`.
//!
//! The planted vtable @ 0x089a3788 is the base message vtable: its live
//! slots point at 0x0828ef34 and the 0x08102f60..0x08103348 cluster beside
//! the queued-message machinery, corroborating the "message base" reading.
//!
//! # Deviations
//!
//! None. The root constructor @ 0x08275bb8 is already ported as
//! [`framework_object_construct`] (`cxx/observable_array.rs`) and is called
//! directly, so no dispatch seam exists here; its root-vtable store is
//! dead exactly as in the original, which overwrites it one instruction
//! later. The single `stmia` is emitted as two ordered volatile stores,
//! the same idiom `observable_array_construct` uses for its four stores.

use crate::cxx::observable_array::{framework_object_construct, FrameworkObject};

/// The vtable planted by [`message_kind_construct`] (original: the
/// literal-pool word @ 0x08266a60). Kept as a plain `u32` address constant
/// because nothing in the crate dereferences it.
pub const MESSAGE_KIND_VTABLE: u32 = 0x089a_3788;

/// The 8-byte kind-tagged message base object. Both fields are `u32`, so
/// the layout is target-exact in 64-bit host tests as well.
#[repr(C)]
pub struct MessageKind {
    /// +0x00: the root subobject, whose vtable this class overwrites.
    pub base: FrameworkObject,
    /// +0x04: the caller's message kind/class tag.
    pub kind: u32,
}

/// Target byte size of [`MessageKind`], i.e. the span every call site's
/// storage must cover.
pub const MESSAGE_KIND_SIZE: usize = 0x08;

const _: [u8; 0x00] = [0; core::mem::offset_of!(MessageKind, base)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(MessageKind, kind)];
const _: [u8; MESSAGE_KIND_SIZE] = [0; core::mem::size_of::<MessageKind>()];

/// message_kind_construct — original: `FUN_08266a48` @ 0x08266a48
/// (24 bytes of code + the 4-byte vtable literal @ 0x08266a60;
/// **45 `bl` call sites**).
///
/// Runs the shared framework root constructor, overwrites its root vtable
/// with the base message vtable 0x089a3788, stores `kind` at +0x04, and
/// returns the root constructor's result — which every caller relies on to
/// address its own derived-vtable store. There is no NULL check and no
/// allocation: caller-provided storage is constructed in place.
///
/// # Safety
///
/// `storage` must point to at least [`MESSAGE_KIND_SIZE`] writable,
/// word-aligned bytes, exactly as the original requires of its r0.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_kind_construct(
    storage: *mut MessageKind,
    kind: u32,
) -> *mut MessageKind {
    let this = framework_object_construct(storage.cast()).cast::<MessageKind>();

    core::ptr::addr_of_mut!((*this).base.vtable).write_volatile(MESSAGE_KIND_VTABLE);
    core::ptr::addr_of_mut!((*this).kind).write_volatile(kind);

    this
}

/// message_kind_destruct — original: `thunk_FUN_08275bc8` @ 0x08266a80
/// (4 bytes; **17 `bl` call sites plus one tail `b` @ 0x0811ef8c**,
/// binary-scanned over every ARM B/BL word in `osos.dec` — Ghidra's 17 is
/// the plain-`bl` count only).
///
/// The NON-DELETING destructor of this same message-kind base — the exact
/// counterpart of [`message_kind_construct`], closing the cluster that
/// opens with it:
///
/// ```text
/// 08266a64  cmp r0, #0             @ the deleting destructor: NULL-guarded
/// 08266a68  push {r4, lr}
/// 08266a6c  popeq {r4, pc}
/// 08266a70  bl   0x08275bc8        @ root destructor
/// 08266a74  pop  {r4, lr}
/// 08266a78  mov  r1, #8            @ sizeof(MessageKind)
/// 08266a7c  b    0x08266a84        @ operator-delete path
/// 08266a80  b    0x08275bc8        @ <- the whole function: tail-branch
/// 08266a84  push {r4, r5, r6, lr}  @ the operator-delete veneer follows
/// ```
///
/// The branch target 0x08275bc8 is binary-verified as the framework root
/// destructor, a bare `bx lr` (documented from
/// `framework_object_construct`'s side in `cxx/observable_array.rs`), so
/// the net effect of the thunk is: nothing is read or written and r0
/// passes through unchanged. Ghidra's own 4-byte extent is right — it is
/// a genuine `b <target>` veneer, not a mis-sized body.
///
/// # Call sites and the load-bearing r0
///
/// 0x08266a80 occurs in **no data word** anywhere in the image, so it is
/// never dispatched virtually — every caller binds it statically. The 17
/// `bl` sites come in two shapes:
///
/// - 8 sites are the NULL-guarded heap destroy
///   `push {r4, lr}; popeq {r4, pc}; bl 0x08266a80; mov r4, r0` — the
///   captured r0 is handed to the operator-delete path (e.g. 0x0816f194:
///   `mov r4, r0; bl 0x082669e4; mov r1, r4`), so the pass-through is a
///   real contract, not a cosmetic detail.
/// - 5 sites are end-of-scope teardown of a stack message
///   (`add r0, sp, #N` / `mov r0, sp` immediately before the `bl`) — the
///   RAII scope teardown `node_list_enqueue` records as
///   `thunk_FUN_08275bc8` in its seam list.
///
/// The remaining sites are the same two shapes with the object pointer
/// materialized a few instructions earlier, and the one tail `b` at
/// 0x0811ef8c is a derived destructor chaining into its base.
///
/// Deviations: none structural — the port is the identity on `this`,
/// exactly what `b 0x08275bc8; bx lr` computes, modeled with no call the
/// same way the observable-array destructors model the same root dtor.
/// Its own `link_section` keeps LLVM's identical-code folding from merging
/// it into the other empty-destructor exports (`cxx/trivial_destructor.rs`,
/// `cxx/empty_destructor.rs`).
///
/// # Safety
///
/// The original dereferences nothing, so `this` may be NULL, unaligned, or
/// dangling.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.message_kind_destruct")]
pub unsafe extern "C" fn message_kind_destruct(this: *mut MessageKind) -> *mut MessageKind {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The object plus a guard word on each side, so a store that runs off
    /// either end of the 8-byte object is visible.
    #[repr(C, align(4))]
    struct GuardedStorage {
        words: [u32; 2 + MESSAGE_KIND_SIZE / 4],
    }

    impl GuardedStorage {
        fn poisoned() -> Self {
            Self { words: [0xa5a5_a5a5; 2 + MESSAGE_KIND_SIZE / 4] }
        }

        fn object(&mut self) -> *mut MessageKind {
            unsafe { self.words.as_mut_ptr().add(1).cast() }
        }
    }

    #[test]
    fn plants_base_vtable_and_kind_and_returns_this() {
        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();

        let returned = unsafe { message_kind_construct(object, 0x16) };

        assert_eq!(returned, object, "r0 passes through for the caller's derived-vtable store");
        assert_eq!(
            storage.words,
            [0xa5a5_a5a5, MESSAGE_KIND_VTABLE, 0x16, 0xa5a5_a5a5],
            "vtable at +0x00, kind at +0x04, guards untouched"
        );
    }

    #[test]
    fn stores_every_observed_kind_tag_verbatim() {
        for kind in [0u32, 1, 2, 3, 4, 0x16, 0x17, 0x22, 0x28, 0x20003, 0xffff_ffff] {
            let mut storage = GuardedStorage::poisoned();
            let object = storage.object();

            let returned = unsafe { message_kind_construct(object, kind) };

            assert_eq!(returned, object);
            assert_eq!(unsafe { (*object).base.vtable }, MESSAGE_KIND_VTABLE);
            assert_eq!(unsafe { (*object).kind }, kind, "kind is stored, never interpreted");
        }
    }

    #[test]
    fn destruct_returns_this_for_the_chained_operator_delete() {
        for address in [0usize, 1, 0x0800_0001, 0x089a_3788, usize::MAX] {
            let this = address as *mut MessageKind;
            assert_eq!(unsafe { message_kind_destruct(this) }, this, "{address:#x}");
        }
    }

    #[test]
    fn destruct_touches_no_byte_of_the_message() {
        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();
        unsafe { message_kind_construct(object, 0x16) };
        let before = storage.words;

        let returned = unsafe { message_kind_destruct(object) };

        assert_eq!(returned, object, "r0 passes through");
        assert_eq!(storage.words, before, "the empty body performs no stores");
    }
}
