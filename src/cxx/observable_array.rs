//! The default constructor of retailOS's **observable array** — a
//! polymorphic, growable array of 32-bit elements that broadcasts changes
//! to a list of attached observers. Everything below is decoded from the
//! raw words of `work/firmware/osos.dec`, not from Ghidra.
//!
//! ## The two ported functions
//!
//! - `observable_array_construct` — original: `FUN_08271cec` @ 0x08271cec
//!   (36 bytes: 32 bytes of code plus the 4-byte vtable literal
//!   0x089a5d0c @ 0x08271d10; **82 `bl` call sites, 0 `b`**, binary-scanned
//!   by decoding every B/BL word in the image).
//!
//!   ```text
//!   08271cec  push {r4, lr}
//!   08271cf0  bl   0x08275bb8        @ the root base constructor
//!   08271cf4  ldr  r1, [pc, #0x14]   @ literal @ 0x08271d10 = 0x089a5d0c
//!   08271cf8  str  r1, [r0]          @ addressed off the base ctor's RETURN
//!   08271cfc  mov  r1, #0
//!   08271d00  str  r1, [r0, #4]
//!   08271d04  str  r1, [r0, #8]
//!   08271d08  str  r1, [r0, #0xc]
//!   08271d0c  pop  {r4, pc}          @ returns `this` in r0
//!   08271d10  .word 0x089a5d0c
//!   ```
//!
//! - `framework_object_construct` — original: `FUN_08275bb8` @ 0x08275bb8
//!   (16 bytes: 12 bytes of code plus the 4-byte vtable literal 0x089a5fdc
//!   @ 0x08275bc4; **9 `bl` call sites, 0 `b`**, binary-scanned).
//!   `ldr r1, [pc, #4]; str r1, [r0]; bx lr` — it plants the root vtable
//!   and nothing else. All nine callers (0x08125238, 0x081433ac,
//!   0x081b1270, 0x08266a50, 0x0826bad0, 0x0826bffc, 0x08271ca0,
//!   0x08271cf0, 0x08275cd8) immediately follow it with their own
//!   `ldr r1, [pc, #N]; str r1, [r0]`, i.e. all nine are derived-class
//!   constructors overwriting the root vtable with their own. Its matching
//!   destructor @ 0x08275bc8 is a bare `bx lr`. So this is the abstract
//!   root of a class hierarchy, ported here because the array's
//!   constructor is its only interesting caller in this crate and a
//!   dispatch seam for three instructions would be pure ceremony.
//!
//! **r0 passes through both.** `FUN_08275bb8` never touches r0, and
//! `FUN_08271cec` addresses its four stores off the base constructor's
//! *return value*, then returns it. Both ports therefore return `this`
//! rather than being void; `names.yaml` records the same observation from
//! `FUN_0810f9f0`'s side (`sub r4, r0, #4` applied to this call's return).
//!
//! ## How the class was identified
//!
//! The constructor alone only proves "vtable plus three zeroed words". Its
//! three siblings in the same literal-pool neighbourhood pin down what
//! those words are — all three bind the same vtable literal 0x089a5d0c,
//! binary-verified at 0x08271ce8, 0x08271d10 and 0x08271d84:
//!
//! - The **copy constructor** ending at 0x08271ce4 default-constructs,
//!   grows by the source's `+0x04` through 0x082718a4, copies `+0x04`
//!   over, and then `lsl r2, r1, #2` / `ldr r1, [src, #8]` /
//!   `ldr r0, [this, #8]` / `bl 0x08037e00` (`rom_memmove`). Copying
//!   `count * 4` bytes out of `+0x08` makes `+0x04` an element count and
//!   `+0x08` the element storage, with 4-byte elements.
//! - The **destructor** @ 0x08271d2c re-plants the vtable, broadcasts
//!   through 0x082a4ccc, drains the `+0x0c` list with 0x08271724, then
//!   `ldr r0, [this, #8]; cmp r0, #0; blne 0x0802edc8` — it hands `+0x08`
//!   to `free` (ported as `free`, per names.yaml) — and finally zeroes
//!   `+0x04`/`+0x08` and tail-branches to the root destructor 0x08275bc8.
//!   Owned heap storage, confirmed.
//! - 0x082a4ccc is `for (node = this[+0x0c]; node; node = node[+0x10])
//!   call 0x08155d30(node, arg)` — a broadcast walk over a singly linked
//!   list rooted at `+0x0c` and linked at `+0x10`, and 0x08271724 unlinks
//!   one node from exactly that list. Hence "observable": `+0x0c` is the
//!   head of the attached-observer list.
//!
//! The growth helper 0x082718a4 rounds the new length up to the
//! granularity returned by virtual slot +0x70, compares it with the
//! capacity from slot +0xa0 and adjusts through slot +0xc0 — all three of
//! which are NULL in vtable 0x089a5d0c, so the class is abstract and every
//! concrete array is one of the 82 derived constructors' classes.
//!
//! Prior art in this repo used the caller-side role name "drain state"
//! for this object (`app/node_list.rs`, `app/object_dispatch_entry.rs`,
//! and their `names.yaml` entries), from the one caller whose use of it is
//! a drain. It is the same class; both of those modules now construct it
//! through this port instead of open-coding or stubbing it.
//!
//! Deviations: none. Both ports write the same words in the same order and
//! return the same register. The vtable addresses are plain `u32`
//! constants because nothing in the crate dereferences them.

/// The vtable planted by [`observable_array_construct`] (original: the
/// literal @ 0x08271d10, and the same word @ 0x08271ce8 and 0x08271d84).
pub const OBSERVABLE_ARRAY_VTABLE: u32 = 0x089a_5d0c;

/// The vtable planted by [`framework_object_construct`] (original: the
/// literal @ 0x08275bc4).
pub const FRAMEWORK_OBJECT_VTABLE: u32 = 0x089a_5fdc;

/// The abstract root object: one vtable word and no state.
#[repr(C)]
pub struct FrameworkObject {
    /// +0x00: vtable pointer, as a target-width word.
    pub vtable: u32,
}

/// The 16-byte observable array. Every field is a `u32` so the layout stays
/// target-exact in 64-bit host tests, where a real pointer would not fit.
#[repr(C)]
pub struct ObservableArray {
    /// +0x00: the root subobject, whose vtable this class overwrites.
    pub base: FrameworkObject,
    /// +0x04: number of 4-byte elements currently in [`Self::storage`].
    pub len: u32,
    /// +0x08: heap storage for the elements; NULL until the first growth,
    /// and released with `free` by the destructor @ 0x08271d2c.
    pub storage: u32,
    /// +0x0c: head of the attached-observer list, linked at observer+0x10
    /// and walked by the broadcast @ 0x082a4ccc.
    pub observers: u32,
}

/// Target byte size of [`ObservableArray`], i.e. the span the constructor
/// initializes.
pub const OBSERVABLE_ARRAY_SIZE: usize = 0x10;

const _: [u8; 0x00] = [0; core::mem::offset_of!(ObservableArray, base)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(ObservableArray, len)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ObservableArray, storage)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ObservableArray, observers)];
const _: [u8; OBSERVABLE_ARRAY_SIZE] = [0; core::mem::size_of::<ObservableArray>()];
const _: [u8; 0x04] = [0; core::mem::size_of::<FrameworkObject>()];

/// framework_object_construct — original: `FUN_08275bb8` @ 0x08275bb8
/// (16 bytes; 9 `bl` call sites, binary-scanned).
///
/// Plants the root vtable and returns `this` untouched in r0, which every
/// caller relies on to address its own vtable store.
///
/// # Safety
///
/// `this` must point to at least four writable, word-aligned bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn framework_object_construct(
    this: *mut FrameworkObject,
) -> *mut FrameworkObject {
    core::ptr::addr_of_mut!((*this).vtable).write_volatile(FRAMEWORK_OBJECT_VTABLE);
    this
}

/// observable_array_construct — original: `FUN_08271cec` @ 0x08271cec
/// (36 bytes; 82 `bl` call sites, binary-scanned).
///
/// Runs the root constructor, overwrites its vtable with the array's own,
/// and leaves an empty array with no storage and no observers. There is no
/// allocation here: `storage` stays NULL until the first growth through
/// virtual slot +0xc0.
///
/// The four stores are addressed off the value the base constructor
/// returned, exactly as the stock `str r1, [r0]` does, rather than off a
/// saved copy of the incoming pointer.
///
/// # Safety
///
/// `this` must point to at least [`OBSERVABLE_ARRAY_SIZE`] writable,
/// word-aligned bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_construct(
    this: *mut ObservableArray,
) -> *mut ObservableArray {
    let array = framework_object_construct(core::ptr::addr_of_mut!((*this).base))
        .cast::<ObservableArray>();

    core::ptr::addr_of_mut!((*array).base.vtable).write_volatile(OBSERVABLE_ARRAY_VTABLE);
    core::ptr::addr_of_mut!((*array).len).write_volatile(0);
    core::ptr::addr_of_mut!((*array).storage).write_volatile(0);
    core::ptr::addr_of_mut!((*array).observers).write_volatile(0);
    array
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The object plus a guard word on each side, so a store that runs off
    /// either end of the 16-byte object is visible.
    #[repr(C, align(4))]
    struct GuardedStorage {
        words: [u32; 2 + OBSERVABLE_ARRAY_SIZE / 4],
    }

    impl GuardedStorage {
        fn poisoned() -> Self {
            Self { words: [0xa5a5_a5a5; 2 + OBSERVABLE_ARRAY_SIZE / 4] }
        }

        fn object(&mut self) -> *mut ObservableArray {
            unsafe { self.words.as_mut_ptr().add(1).cast() }
        }
    }

    #[test]
    fn the_root_constructor_plants_one_word_and_returns_this() {
        let mut storage = GuardedStorage::poisoned();
        let object = storage.object().cast::<FrameworkObject>();

        let returned = unsafe { framework_object_construct(object) };

        assert_eq!(returned, object, "r0 passes through for the caller's vtable store");
        assert_eq!(storage.words, [0xa5a5_a5a5, FRAMEWORK_OBJECT_VTABLE, 0xa5a5_a5a5, 0xa5a5_a5a5, 0xa5a5_a5a5, 0xa5a5_a5a5]);
    }

    #[test]
    fn construction_leaves_an_empty_array_with_no_storage_and_no_observers() {
        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();

        let returned = unsafe { observable_array_construct(object) };

        assert_eq!(returned, object, "the constructor returns `this`");
        assert_eq!(
            storage.words,
            [0xa5a5_a5a5, OBSERVABLE_ARRAY_VTABLE, 0, 0, 0, 0xa5a5_a5a5],
            "the derived vtable wins over the root's, and nothing outside +0x00..+0x0f moves"
        );
    }

    #[test]
    fn a_reconstructed_array_forgets_its_previous_storage_and_observers() {
        // Constructing over a live array leaks its buffer and orphans its
        // observers: the stock constructor overwrites, it does not release.
        // This is the behavior the destructor @ 0x08271d2c exists to avoid.
        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();
        unsafe {
            (*object).len = 7;
            (*object).storage = 0x0800_1000;
            (*object).observers = 0x0800_2000;

            observable_array_construct(object);

            assert_eq!((*object).len, 0);
            assert_eq!((*object).storage, 0, "the previous buffer is dropped, not freed");
            assert_eq!((*object).observers, 0, "attached observers are orphaned, not detached");
        }
    }
}
