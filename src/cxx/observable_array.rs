//! The default constructor of retailOS's **observable array** — a
//! polymorphic, growable array of 32-bit elements that broadcasts changes
//! to a list of attached observers. Everything below is decoded from the
//! raw words of `work/firmware/osos.dec`, not from Ghidra.
//!
//! ## The ported functions
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
//! - `observable_array_destruct` — original: `FUN_08271d2c` @ 0x08271d2c
//!   (**92 bytes**, not Ghidra's 88: 88 bytes of code, 0x08271d2c..0x08271d80,
//!   plus the 4-byte vtable literal 0x089a5d0c @ 0x08271d84, with the next
//!   function starting at 0x08271d88. **60 `bl` and 42 `b` call sites**,
//!   binary-scanned by decoding every B/BL word in `osos.dec` — the 42
//!   tail-branches are derived-class destructors chaining into their base.)
//!
//!   ```text
//!   08271d2c  push  {r4, lr}
//!   08271d30  mov   r4, r0
//!   08271d34  ldr   r0, [pc, #72]     @ literal @ 0x08271d84 = 0x089a5d0c
//!   08271d38  mov   r1, #0
//!   08271d3c  str   r0, [r4]          @ re-plant this class's vtable
//!   08271d40  mov   r0, r4
//!   08271d44  bl    0x082a4ccc        @ notify(this, 0) — broadcast
//!   08271d48  b     0x08271d54
//!   08271d4c  mov   r0, r4            @ r1 still holds the head from below
//!   08271d50  bl    0x08271724        @ detach(this, head)
//!   08271d54  ldr   r1, [r4, #0xc]
//!   08271d58  cmp   r1, #0
//!   08271d5c  bne   0x08271d4c
//!   08271d60  ldr   r0, [r4, #8]
//!   08271d64  cmp   r0, #0
//!   08271d68  blne  0x0802edc8        @ free(storage)
//!   08271d6c  mov   r0, #0
//!   08271d70  str   r0, [r4, #4]
//!   08271d74  str   r0, [r4, #8]
//!   08271d78  mov   r0, r4
//!   08271d7c  pop   {r4, lr}
//!   08271d80  b     0x08275bc8        @ the root destructor: a bare `bx lr`
//!   08271d84  .word 0x089a5d0c
//!   ```
//!
//!   Ghidra's C (`decomp/c/026/08271d2c_FUN_08271d2c.c`) is wrong twice and
//!   both errors matter. It renders the free as `FUN_0802edc8()` with **no
//!   argument** — the real code passes `this->storage` in r0 — and it renders
//!   the drain as `FUN_08271724(param_1)` with one, when `r1` is live across
//!   the loop: the `ldr r1, [r4, #0xc]` that tests the head is also the
//!   second argument of the next iteration's call. The loop is
//!   `while ((head = this->observers)) detach(this, head)`.
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

/// Word index of an observer node's next link (`node + 0x10`), the link
/// the broadcast @ 0x082a4ccc walks and the detach @ 0x08271724 splices.
const OBSERVER_NEXT_WORD: usize = 4;

/// Indirect call to the unported observer broadcast `FUN_082a4ccc` @
/// 0x082a4ccc (40 bytes): `for (n = this->observers; n; n = n[+0x10])
/// FUN_08155d30(n, reason)`. The destructor invokes it with `reason == 0`
/// before detaching anything, so every attached observer learns the array
/// is going away while the list is still intact.
///
/// Its own callee 0x08155d30 is unported, so the wired default is a no-op
/// — the `ITERATOR_STATE_RELEASE` precedent. Nothing in the destructor's
/// control flow depends on the broadcast's effects, so an unswapped
/// default only means "no observer is notified".
pub static mut OBSERVABLE_ARRAY_NOTIFY: unsafe extern "C" fn(
    this: *mut ObservableArray,
    reason: u32,
) = observable_array_notify_unported;

/// Default for [`OBSERVABLE_ARRAY_NOTIFY`]: the broadcast is unported, so
/// it has no local effect.
unsafe extern "C" fn observable_array_notify_unported(_this: *mut ObservableArray, _reason: u32) {}

/// Indirect call to the observer-list unlink `FUN_08271724` @ 0x08271724
/// (64 bytes), which walks `owner->observers` and splices `target` out by
/// its `+0x10` next link.
///
/// **The wired default is not a no-op**, and it must not be. The
/// destructor calls this with `target == owner->observers` on every
/// iteration (the `ldr r1, [r4, #0xc]` that tests the loop condition is
/// the argument), so the only branch of 0x08271724 this site can ever
/// reach is its head match — `owner->observers = target->next` — and that
/// store is exactly what makes the drain terminate. A no-op default would
/// turn the destructor into an infinite loop over any non-empty observer
/// list. The default therefore implements that one branch; when the full
/// 0x08271724 lands (`names.yaml` records it as `iterator_state_release`
/// in `app/vtable_set`, though no such function exists in the tree yet —
/// only the no-op `ITERATOR_STATE_RELEASE` seam) it replaces the default
/// here and the general walk covers this case identically.
pub static mut OBSERVABLE_ARRAY_DETACH_OBSERVER: unsafe extern "C" fn(
    owner: *mut ObservableArray,
    target: *mut u8,
) = observable_array_detach_observer_head;

/// Default for [`OBSERVABLE_ARRAY_DETACH_OBSERVER`]: the head-match branch
/// of 0x08271724, the only one reachable from the destructor's drain.
unsafe extern "C" fn observable_array_detach_observer_head(
    owner: *mut ObservableArray,
    target: *mut u8,
) {
    let next = target.cast::<u32>().add(OBSERVER_NEXT_WORD).read_volatile();
    core::ptr::addr_of_mut!((*owner).observers).write_volatile(next);
}

/// The array's element-storage release, wired to the ported `free` @
/// 0x0802edc8 (`runtime/malloc_rt`) exactly as the original's
/// `blne 0x0802edc8` binds it. Indirected only so host tests can observe
/// the pointer handed over without routing a fixture address into the
/// firmware heap — the `runtime/shutdown_chain::SHUTDOWN_FREE` and
/// `stdio/stream_file::STDIO_FREE` precedent.
pub static mut OBSERVABLE_ARRAY_FREE: unsafe extern "C" fn(ptr: *mut u8) =
    crate::runtime::malloc_rt::free;

/// observable_array_destruct — original: `FUN_08271d2c` @ 0x08271d2c
/// (92 bytes: 88 of code plus the vtable literal @ 0x08271d84; 60 `bl`
/// and 42 `b` call sites, binary-scanned).
///
/// The destructor of the class [`observable_array_construct`] builds, and
/// the mirror image of it:
///
/// ```text
/// this->vtable = OBSERVABLE_ARRAY_VTABLE   ; re-plant, so a derived
///                                          ; destructor's virtual calls
///                                          ; land on this class
/// notify(this, 0)                          ; broadcast over the intact list
/// while ((head = this->observers))         ; drain: detach the head until
///     detach(this, head)                   ; the list is empty
/// if (this->storage) free(this->storage)   ; the owned element buffer
/// this->len = 0; this->storage = 0
/// return this
/// ```
///
/// Three details are load-bearing:
///
/// - The vtable store comes **first**, before the broadcast — the standard
///   C++ destructor prologue, so any virtual dispatch during teardown
///   resolves in this class rather than in the derived one being unwound.
/// - The drain passes the **head node** as the second argument. Ghidra
///   dropped it (see the module header); `r1` is live from the loop's own
///   `ldr r1, [r4, #0xc]`.
/// - `observers` (+0x0c) is never explicitly zeroed. It does not need to
///   be: the loop only exits when the head is already 0. The final stores
///   clear `len` and `storage` only, and the vtable word is left planted.
///
/// The tail `b 0x08275bc8` into the root destructor is binary-verified a
/// bare `bx lr` (the same one `framework_object_construct`'s notes record),
/// so it is the identity on r0 and the port models it as the plain
/// `return this` it is, with no call. Callers depend on that return: of the
/// 102 sites, the 42 `b` are derived destructors tail-chaining here and
/// several `bl` sites feed r0 straight into `operator_delete`.
///
/// # Safety
///
/// `this` must point to a live [`ObservableArray`] — [`OBSERVABLE_ARRAY_SIZE`]
/// writable, word-aligned bytes. Every observer reachable from
/// `this->observers` must have a readable word at `+0x10`, and `storage`,
/// when nonzero, must be a pointer the wired free accepts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_destruct(
    this: *mut ObservableArray,
) -> *mut ObservableArray {
    core::ptr::addr_of_mut!((*this).base.vtable).write_volatile(OBSERVABLE_ARRAY_VTABLE);

    let notify = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_NOTIFY));
    notify(this, 0);

    let detach = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_DETACH_OBSERVER));
    loop {
        let head = core::ptr::addr_of!((*this).observers).read_volatile();
        if head == 0 {
            break;
        }
        detach(this, head as usize as *mut u8);
    }

    let storage = core::ptr::addr_of!((*this).storage).read_volatile();
    if storage != 0 {
        let free = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_FREE));
        free(storage as usize as *mut u8);
    }

    core::ptr::addr_of_mut!((*this).len).write_volatile(0);
    core::ptr::addr_of_mut!((*this).storage).write_volatile(0);
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Mutex;
    use std::vec::Vec;

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

    // --- the destructor @ 0x08271d2c -------------------------------------

    /// One entry of the teardown trace, so the target's ORDER — vtable,
    /// broadcast, drain, free — is provable and not just its effects.
    #[derive(Debug, PartialEq, Eq)]
    enum Step {
        /// `notify(this, reason)`, with the vtable word as the broadcast
        /// observed it.
        Notify { reason: u32, vtable: u32 },
        /// `detach(this, target)`.
        Detach { target: u32 },
        /// `free(ptr)`.
        Free { ptr: u32 },
    }

    static TRACE: Mutex<Vec<Step>> = Mutex::new(Vec::new());

    /// Serializes the three seam swaps below: they are crate-global
    /// statics and `cargo test` runs these tests on parallel threads.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn recording_notify(this: *mut ObservableArray, reason: u32) {
        let vtable = core::ptr::addr_of!((*this).base.vtable).read_volatile();
        TRACE.lock().unwrap().push(Step::Notify { reason, vtable });
    }

    unsafe extern "C" fn recording_detach(owner: *mut ObservableArray, target: *mut u8) {
        TRACE.lock().unwrap().push(Step::Detach { target: target as usize as u32 });
        observable_array_detach_observer_head(owner, target);
    }

    unsafe extern "C" fn recording_free(ptr: *mut u8) {
        TRACE.lock().unwrap().push(Step::Free { ptr: ptr as usize as u32 });
    }

    /// Restores the wired defaults on drop, even when a test panics.
    struct SeamGuard;
    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_NOTIFY)
                    .write_volatile(observable_array_notify_unported);
                core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_DETACH_OBSERVER)
                    .write_volatile(observable_array_detach_observer_head);
                core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_FREE)
                    .write_volatile(crate::runtime::malloc_rt::free);
            }
        }
    }

    /// Swaps all three seams for recorders and clears the trace.
    fn install_recorders() -> SeamGuard {
        unsafe {
            core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_NOTIFY).write_volatile(recording_notify);
            core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_DETACH_OBSERVER)
                .write_volatile(recording_detach);
            core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_FREE).write_volatile(recording_free);
        }
        TRACE.lock().unwrap().clear();
        SeamGuard
    }

    fn trace() -> Vec<Step> {
        core::mem::take(&mut *TRACE.lock().unwrap())
    }

    /// Observer nodes must be addressable through the array's u32
    /// `observers` word, so they live in a sub-4-GiB slab. Each node is
    /// five words; only `+0x10` (word 4) is read.
    const NODE_WORDS: usize = 5;
    const NODES: usize = 3;

    /// Builds a chain of `count` observer nodes in the slab and returns
    /// their target addresses, head first.
    unsafe fn chain(slab: *mut u8, count: usize) -> Vec<u32> {
        let words = slab.cast::<u32>();
        let addrs: Vec<u32> = (0..count)
            .map(|i| slab.add(i * NODE_WORDS * 4) as usize as u32)
            .collect();
        for i in 0..count {
            let next = if i + 1 < count { addrs[i + 1] } else { 0 };
            words.add(i * NODE_WORDS + OBSERVER_NEXT_WORD).write_volatile(next);
        }
        addrs
    }

    #[test]
    fn destruction_of_an_empty_array_broadcasts_once_and_frees_nothing() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seams = install_recorders();

        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();
        unsafe {
            observable_array_construct(object);
            (*object).len = 4;

            let returned = observable_array_destruct(object);
            assert_eq!(returned, object, "the tail `b` into the bare `bx lr` root leaves r0");
        }

        assert_eq!(
            trace(),
            [Step::Notify { reason: 0, vtable: OBSERVABLE_ARRAY_VTABLE }],
            "the broadcast runs with reason 0, and the vtable is already re-planted"
        );
        assert_eq!(
            storage.words,
            [0xa5a5_a5a5, OBSERVABLE_ARRAY_VTABLE, 0, 0, 0, 0xa5a5_a5a5],
            "len and storage are cleared, the vtable word survives, guards untouched"
        );
    }

    #[test]
    fn a_nonzero_storage_pointer_is_handed_to_free_and_then_cleared() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seams = install_recorders();

        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();
        unsafe {
            observable_array_construct(object);
            (*object).len = 9;
            (*object).storage = 0x0801_2340;

            observable_array_destruct(object);

            assert_eq!((*object).storage, 0);
            assert_eq!((*object).len, 0);
        }

        assert_eq!(
            trace(),
            [
                Step::Notify { reason: 0, vtable: OBSERVABLE_ARRAY_VTABLE },
                Step::Free { ptr: 0x0801_2340 },
            ],
            "free receives the element buffer — the argument Ghidra dropped"
        );
    }

    #[test]
    fn a_null_storage_pointer_skips_the_free_entirely() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _seams = install_recorders();

        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();
        unsafe {
            observable_array_construct(object);
            observable_array_destruct(object);
        }

        assert_eq!(
            trace(),
            [Step::Notify { reason: 0, vtable: OBSERVABLE_ARRAY_VTABLE }],
            "the original's `cmp r0, #0; blne` guards the call, not just free's own NULL check"
        );
    }

    #[test]
    fn the_drain_detaches_every_observer_head_until_the_list_is_empty() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slab = match crate::testing::try_map_u32_slab(
            crate::testing::hints::OBSERVABLE_ARRAY,
            NODES * NODE_WORDS * 4,
        ) {
            Some(slab) => slab,
            None => {
                crate::testing::note_missing_u32_fixture("cxx::observable_array");
                return;
            }
        };
        let _seams = install_recorders();

        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();
        let nodes = unsafe { chain(slab, NODES) };
        unsafe {
            observable_array_construct(object);
            (*object).observers = nodes[0];
            (*object).storage = 0x0801_2340;

            observable_array_destruct(object);

            assert_eq!((*object).observers, 0, "the loop exits only on an empty head");
        }

        assert_eq!(
            trace(),
            [
                Step::Notify { reason: 0, vtable: OBSERVABLE_ARRAY_VTABLE },
                Step::Detach { target: nodes[0] },
                Step::Detach { target: nodes[1] },
                Step::Detach { target: nodes[2] },
                Step::Free { ptr: 0x0801_2340 },
            ],
            "broadcast over the intact list first, then drain head-first, then free"
        );
    }

    #[test]
    fn the_wired_detach_default_terminates_a_single_observer_drain() {
        // No detach recorder here: this is the DEFAULT seam, and a no-op
        // default would hang instead of returning.
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slab = match crate::testing::try_map_u32_slab(
            crate::testing::hints::OBSERVABLE_ARRAY,
            NODES * NODE_WORDS * 4,
        ) {
            Some(slab) => slab,
            None => {
                crate::testing::note_missing_u32_fixture("cxx::observable_array");
                return;
            }
        };

        let mut storage = GuardedStorage::poisoned();
        let object = storage.object();
        let nodes = unsafe { chain(slab, 1) };
        unsafe {
            observable_array_construct(object);
            (*object).observers = nodes[0];

            observable_array_destruct(object);

            assert_eq!((*object).observers, 0);
        }
    }
}
