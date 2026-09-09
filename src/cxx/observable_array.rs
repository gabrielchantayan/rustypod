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
//! - `observable_array_copy_construct` — original: `FUN_08271c98` @
//!   0x08271c98 (**84 bytes**, not Ghidra's 80: 80 instruction bytes plus
//!   the 4-byte shared vtable literal 0x089a5d0c @ 0x08271ce8; **13 `bl`
//!   and 2 tail `b` call sites**, all unconditional, binary-scanned by
//!   decoding every B/BL word in the image). It first performs the same
//!   base/vtable/zero initialization as the default constructor, grows its
//!   owned storage by the source element count through unported
//!   `FUN_082718a4`, then copies exactly `count * 4` bytes from the source
//!   storage through the ported ROM-memmove target. The count is reloaded
//!   after growth before both the destination count store and the byte
//!   count, exactly as the raw instructions do. The unported grow helper is
//!   a direct target seam; target builds call its verified load address and
//!   host tests install a real allocating model. No callee identity beyond
//!   its observed growth behaviour is claimed.
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

/// Host model of the virtual slot that concrete observable-array classes
/// supply at target vtable offset `+0xbc`.
///
/// Firmware vtable pointers are `u32` words, while host function pointers
/// are wider. This separate host-only representation keeps the production
/// [`ObservableArray`] layout target-exact and lets tests dispatch the same
/// virtual operation structurally.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ObservableArrayClearHost {
    /// Host pointer standing in for the target's first-word vtable address.
    pub vtable: *const ObservableArrayClearVtable,
    /// The target's array length at `this + 0x04`.
    pub len: u32,
}

/// Recovered portion of the concrete observable-array vtable.
///
/// On 32-bit ARM, [`Self::remove_tail`] is exactly offset `+0xbc`. `usize`
/// filler words preserve that target offset and keep the host fields
/// separately addressable.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ObservableArrayClearVtable {
    /// Slots `+0x00..+0xb8`, not dispatched by this wrapper.
    pub unresolved_00_b8: [usize; 47],
    /// `+0xbc`: removes a signed number of elements from the tail.
    pub remove_tail: unsafe extern "C" fn(*mut ObservableArray, i32),
}

#[cfg(all(not(target_arch = "arm"), target_pointer_width = "32"))]
const _: [u8; 0xbc] = [0; core::mem::offset_of!(ObservableArrayClearVtable, remove_tail)];
/// Firmware ABI of the append path's vtable slots. The names describe the
/// observed call role, not an invented identity for a runtime target.
pub type ObservableArrayAppendDeferred =
    unsafe extern "C" fn(*mut ObservableArray, i32, *mut u8) -> u32;
pub type ObservableArrayAppendIsDeferred = unsafe extern "C" fn(*mut ObservableArray) -> u32;
pub type ObservableArrayAppendResize = unsafe extern "C" fn(*mut ObservableArray, i32);
pub type ObservableArrayAppendWrite =
    unsafe extern "C" fn(*mut ObservableArray, u32, *mut u8);
pub type ObservableArrayAppendFinish = unsafe extern "C" fn(*mut ObservableArray, u32);

/// Host model of the observable-array prefix used by
/// [`observable_array_append`].
///
/// The real vtable word is target-width; this native-pointer replacement is
/// only for host tests of the recovered virtual call sequence.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ObservableArrayAppendHost {
    pub vtable: *const ObservableArrayAppendVtable,
    pub len: u32,
}

/// Recovered virtual slots used by [`observable_array_append`].
///
/// On a 32-bit target the named fields occupy their retailOS offsets
/// `+0x20`, `+0x60`, `+0x88`, `+0xa8`, and `+0xbc`; unobserved slots are
/// retained as word-sized fillers. On a 64-bit host the wider native
/// callbacks intentionally make this a structural test model instead.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ObservableArrayAppendVtable {
    pub unresolved_00_1c: [usize; 8],
    pub append_deferred: ObservableArrayAppendDeferred,
    pub unresolved_24_5c: [usize; 15],
    pub append_is_deferred: ObservableArrayAppendIsDeferred,
    pub unresolved_64_84: [usize; 9],
    pub append_finish: ObservableArrayAppendFinish,
    pub unresolved_8c_a4: [usize; 7],
    pub append_write: ObservableArrayAppendWrite,
    pub unresolved_ac_b8: [usize; 4],
    pub append_resize: ObservableArrayAppendResize,
}

#[cfg(all(not(target_arch = "arm"), target_pointer_width = "32"))]
const _: [u8; 0x20] = [0; core::mem::offset_of!(ObservableArrayAppendVtable, append_deferred)];
#[cfg(all(not(target_arch = "arm"), target_pointer_width = "32"))]
const _: [u8; 0x60] = [0; core::mem::offset_of!(ObservableArrayAppendVtable, append_is_deferred)];
#[cfg(all(not(target_arch = "arm"), target_pointer_width = "32"))]
const _: [u8; 0x88] = [0; core::mem::offset_of!(ObservableArrayAppendVtable, append_finish)];
#[cfg(all(not(target_arch = "arm"), target_pointer_width = "32"))]
const _: [u8; 0xa8] = [0; core::mem::offset_of!(ObservableArrayAppendVtable, append_write)];
#[cfg(all(not(target_arch = "arm"), target_pointer_width = "32"))]
const _: [u8; 0xbc] = [0; core::mem::offset_of!(ObservableArrayAppendVtable, append_resize)];

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

/// Firmware load address of the unported observable-array growth helper
/// `FUN_082718a4`, which the copy constructor calls after default setup.
pub const OBSERVABLE_ARRAY_GROW_ADDRESS: usize = 0x0827_18a4;

/// Target default for [`OBSERVABLE_ARRAY_GROW`]: the stock growth helper.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_observable_array_grow(this: *mut ObservableArray, additional: i32) {
    let grow: unsafe extern "C" fn(*mut ObservableArray, i32) =
        core::mem::transmute(OBSERVABLE_ARRAY_GROW_ADDRESS);
    grow(this, additional);
}

/// Host default for [`OBSERVABLE_ARRAY_GROW`]: the helper remains unported.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_observable_array_grow(
    _this: *mut ObservableArray,
    _additional: i32,
) {
    panic!("observable_array_copy_construct requires growth helper 0x082718a4")
}

/// Direct-call boundary for the unported growth helper `FUN_082718a4`.
///
/// Its true behaviour is verified from raw ARM: it queries virtual slots
/// `+0x70`, `+0xa0`, and `+0xc0` to resize storage, then updates `len`.
/// This copy constructor immediately overwrites `len` with its fresh source
/// value, but still requires the helper's storage allocation. A later port
/// replaces this seam with the helper without changing this caller.
#[cfg(target_os = "none")]
pub static mut OBSERVABLE_ARRAY_GROW: unsafe extern "C" fn(
    this: *mut ObservableArray,
    additional: i32,
) = firmware_observable_array_grow;

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_GROW: unsafe extern "C" fn(
    this: *mut ObservableArray,
    additional: i32,
) = missing_observable_array_grow;

/// observable_array_copy_construct — original: `FUN_08271c98` @ 0x08271c98
/// (84 bytes: 80 bytes of code, 0x08271c98..0x08271ce4, plus the shared
/// 4-byte vtable literal @ 0x08271ce8; 13 unconditional `bl` and 2
/// unconditional tail `b` call sites, binary-scanned).
///
/// Default-constructs `destination`, asks `FUN_082718a4` to grow it by
/// `source->len`, reloads that count, and copies exactly `count * 4` bytes
/// from `source->storage` into the newly allocated destination storage. The
/// source's vtable and observer list are deliberately not copied. The
/// count's byte conversion is ARM `lsl #2`, hence wraps modulo $2^{32}$.
///
/// Deliberate deviation: the unported direct callee is represented by
/// [`OBSERVABLE_ARRAY_GROW`], wired to its verified firmware address on
/// target and a test model on host. It has no inferred semantic identity
/// beyond its binary-observed array-growth role.
///
/// # Safety
///
/// `destination` must point to [`OBSERVABLE_ARRAY_SIZE`] writable,
/// word-aligned bytes. `source` must point to a readable array prefix; its
/// storage word must name at least `source->len * 4` readable bytes, and the
/// growth helper must establish that many writable bytes in `destination`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_copy_construct(
    destination: *mut ObservableArray,
    source: *const ObservableArray,
) -> *mut ObservableArray {
    let array = framework_object_construct(core::ptr::addr_of_mut!((*destination).base))
        .cast::<ObservableArray>();

    core::ptr::addr_of_mut!((*array).base.vtable).write_volatile(OBSERVABLE_ARRAY_VTABLE);
    core::ptr::addr_of_mut!((*array).len).write_volatile(0);
    core::ptr::addr_of_mut!((*array).storage).write_volatile(0);
    core::ptr::addr_of_mut!((*array).observers).write_volatile(0);

    let initial_count = core::ptr::addr_of!((*source).len).read_volatile();
    let grow = core::ptr::addr_of!(OBSERVABLE_ARRAY_GROW).read_volatile();
    grow(array, initial_count as i32);

    let count = core::ptr::addr_of!((*source).len).read_volatile();
    core::ptr::addr_of_mut!((*array).len).write_volatile(count);
    let byte_count = count.wrapping_shl(2) as usize;
    let source_storage = core::ptr::addr_of!((*source).storage).read_volatile() as usize as *const u8;
    let destination_storage =
        core::ptr::addr_of!((*array).storage).read_volatile() as usize as *mut u8;
    crate::libc::memmove::memmove(destination_storage, source_storage, byte_count);
    array
}

/// observable_array_clear — original: `FUN_08271c84` @ `0x08271c84`
/// (20 bytes; **19 `bl` and 57 tail `b` call sites**, all unconditional,
/// binary-scanned by decoding every B/BL word in `osos.dec`).
///
/// Loads `this->len`, negates it with ARM's wrapping `rsb r1, r1, #0`, then
/// tail-dispatches the concrete array's vtable slot `+0xbc`. That slot is the
/// array's signed tail-removal operation, so the negative current length
/// clears the array. The wrapper has no NULL guard for `this`, its vtable, or
/// the slot. Its true extent is exactly 20 instruction bytes
/// (`0x08271c84..0x08271c94`): the next independent function starts at
/// `0x08271c98`; no literal pool follows.
///
/// Deliberate host deviation: [`ObservableArray`] retains its target-exact
/// `u32` vtable word, so host tests use [`ObservableArrayClearHost`] to model
/// the wider vtable pointer structurally. The ARM implementation below is the
/// raw five-instruction tail dispatch, preserving the virtual method's return
/// register and avoiding a local return edge.
///
/// # Safety
///
/// On ARM, `this` must be a readable concrete observable array with a valid
/// vtable slot `+0xbc` accepting `(this, -this->len)`. On host, it must point
/// to a valid [`ObservableArrayClearHost`] model.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn observable_array_clear(this: *mut ObservableArray) {
    let array = this.cast::<ObservableArrayClearHost>();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*array).vtable));
    let len = core::ptr::read_volatile(core::ptr::addr_of!((*array).len));
    ((*vtable).remove_tail)(this, len.wrapping_neg() as i32);
}

// The retail wrapper ends in `bx r2`, not `blx r2; bx lr`: retain the exact
// tail dispatch and its return register for hooked target builds.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl observable_array_clear
    .type observable_array_clear, %function
observable_array_clear:
    ldr     r2, [r0]
    ldr     r1, [r0, #4]
    ldr     r2, [r2, #0xbc]
    rsb     r1, r1, #0
    bx      r2
    .size observable_array_clear, . - observable_array_clear
"#
);

/// Load address of the unported append observer broadcast
/// `FUN_082a4ca0`. It walks `this->observers` and calls 0x08155cc8 for each
/// node with the appended index.
pub const OBSERVABLE_ARRAY_NOTIFY_APPEND_ADDRESS: usize = 0x082a_4ca0;

/// Target default for [`OBSERVABLE_ARRAY_NOTIFY_APPEND`]: the retailOS
/// observer broadcast remains mapped at its load address.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_observable_array_notify_append(
    this: *mut ObservableArray,
    index: u32,
) {
    let notify: unsafe extern "C" fn(*mut ObservableArray, u32) =
        core::mem::transmute(OBSERVABLE_ARRAY_NOTIFY_APPEND_ADDRESS);
    notify(this, index);
}

/// Host default for [`OBSERVABLE_ARRAY_NOTIFY_APPEND`]: host callers must
/// install their own observer model because the retailOS callback remains
/// unported.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_observable_array_notify_append(
    _this: *mut ObservableArray,
    _index: u32,
) {
    panic!("observable_array_append requires observer broadcast 0x082a4ca0")
}

/// Direct-call boundary for the unported observer broadcast 0x082a4ca0.
///
/// Target builds dispatch to the still-mapped retailOS function; host tests
/// install a recorder. A later port can replace this seam without changing
/// the append wrapper.
#[cfg(target_os = "none")]
pub static mut OBSERVABLE_ARRAY_NOTIFY_APPEND: unsafe extern "C" fn(
    this: *mut ObservableArray,
    index: u32,
) = firmware_observable_array_notify_append;

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_NOTIFY_APPEND: unsafe extern "C" fn(
    this: *mut ObservableArray,
    index: u32,
) = missing_observable_array_notify_append;

/// observable_array_append — original: `FUN_0827196c` @ `0x0827196c`
/// (**144 bytes**, 0x0827196c..0x082719f8; the next independent function is
/// the `bx lr` at 0x082719fc; **17 unconditional `bl` and 2 `bleq` call
/// sites**, binary-scanned by decoding every ARM B/BL word in `osos.dec`).
///
/// Appends the opaque value at `element` to a concrete observable array. If
/// vtable slot `+0x60` says append is deferred, tail-dispatch slot `+0x20`
/// with the `0x7fff_ffff` append sentinel and returns its result. Otherwise
/// it snapshots `len`, asks slot `+0xbc` to grow by one, writes the value at
/// that old index through `+0xa8`, broadcasts the index through 0x082a4ca0,
/// finishes through `+0x88` with zero, and returns the old index. The two
/// predicated sites are `bleq` callers: they guard this NULL-free wrapper;
/// the wrapper itself dereferences its receiver and all five vtable slots.
///
/// Deliberate host deviation: [`ObservableArrayAppendHost`] carries a native
/// vtable pointer, while target code reads 32-bit vtable words. The direct
/// observer broadcast is not ported, so target builds call its verified
/// retailOS entry and host builds require a test seam. No word-aligned DATA
/// occurrence of 0x0827196c exists in the image, so this wrapper is never
/// itself reached through a vtable.
///
/// # Safety
///
/// `this` must be a readable concrete observable array whose vtable exposes
/// valid callbacks at `+0x20`, `+0x60`, `+0x88`, `+0xa8`, and `+0xbc`.
/// `element` has the callback-defined element representation; neither branch
/// NULL-checks it.
#[cfg(not(target_arch = "arm"))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_append(
    this: *mut ObservableArray,
    element: *mut u8,
) -> u32 {
    let array = this.cast::<ObservableArrayAppendHost>();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*array).vtable));
    if (vtable.as_ref().unwrap().append_is_deferred)(this) != 0 {
        return (vtable.as_ref().unwrap().append_deferred)(this, 0x7fff_ffff, element);
    }

    let index = core::ptr::read_volatile(core::ptr::addr_of!((*array).len));
    (vtable.as_ref().unwrap().append_resize)(this, 1);
    (vtable.as_ref().unwrap().append_write)(this, index, element);
    let notify = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_NOTIFY_APPEND));
    notify(this, index);
    (vtable.as_ref().unwrap().append_finish)(this, 0);
    index
}

#[cfg(target_arch = "arm")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_append(
    this: *mut ObservableArray,
    element: *mut u8,
) -> u32 {
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*this).base.vtable)) as *const u32;
    let append_is_deferred: ObservableArrayAppendIsDeferred =
        core::mem::transmute(core::ptr::read_volatile(vtable.add(0x60 / 4)));
    if append_is_deferred(this) != 0 {
        let append_deferred: ObservableArrayAppendDeferred =
            core::mem::transmute(core::ptr::read_volatile(vtable.add(0x20 / 4)));
        return append_deferred(this, 0x7fff_ffff, element);
    }

    let index = core::ptr::read_volatile(core::ptr::addr_of!((*this).len));
    let append_resize: ObservableArrayAppendResize =
        core::mem::transmute(core::ptr::read_volatile(vtable.add(0xbc / 4)));
    append_resize(this, 1);
    let append_write: ObservableArrayAppendWrite =
        core::mem::transmute(core::ptr::read_volatile(vtable.add(0xa8 / 4)));
    append_write(this, index, element);
    let notify = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_NOTIFY_APPEND));
    notify(this, index);
    let append_finish: ObservableArrayAppendFinish =
        core::mem::transmute(core::ptr::read_volatile(vtable.add(0x88 / 4)));
    append_finish(this, 0);
    index
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

    static CLEAR_LOCK: Mutex<()> = Mutex::new(());
    static mut CLEAR_CALLS: u32 = 0;
    static mut CLEAR_RECEIVER: *mut ObservableArray = core::ptr::null_mut();
    static mut CLEAR_DELTA: i32 = 0;

    unsafe extern "C" fn record_remove_tail(this: *mut ObservableArray, delta: i32) {
        core::ptr::addr_of_mut!(CLEAR_CALLS).write(CLEAR_CALLS + 1);
        core::ptr::addr_of_mut!(CLEAR_RECEIVER).write(this);
        core::ptr::addr_of_mut!(CLEAR_DELTA).write(delta);
    }

    static CLEAR_VTABLE: ObservableArrayClearVtable = ObservableArrayClearVtable {
        unresolved_00_b8: [0; 47],
        remove_tail: record_remove_tail,
    };

    unsafe fn reset_clear_recording() {
        core::ptr::addr_of_mut!(CLEAR_CALLS).write(0);
        core::ptr::addr_of_mut!(CLEAR_RECEIVER).write(core::ptr::null_mut());
        core::ptr::addr_of_mut!(CLEAR_DELTA).write(0);
    }

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

    static COPY_LOCK: Mutex<()> = Mutex::new(());
    static mut COPY_GROW_CALLS: u32 = 0;
    static mut COPY_GROW_RECEIVER: *mut ObservableArray = core::ptr::null_mut();
    static mut COPY_GROW_ADDITIONAL: i32 = 0;
    static mut COPY_DESTINATION_STORAGE: u32 = 0;

    unsafe extern "C" fn record_copy_grow(this: *mut ObservableArray, additional: i32) {
        core::ptr::addr_of_mut!(COPY_GROW_CALLS).write(COPY_GROW_CALLS + 1);
        core::ptr::addr_of_mut!(COPY_GROW_RECEIVER).write(this);
        core::ptr::addr_of_mut!(COPY_GROW_ADDITIONAL).write(additional);
        core::ptr::addr_of_mut!((*this).storage).write_volatile(COPY_DESTINATION_STORAGE);
    }

    struct CopyGrowGuard;
    impl Drop for CopyGrowGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_GROW)
                    .write_volatile(missing_observable_array_grow);
            }
        }
    }

    unsafe fn install_copy_grow(destination_storage: u32) -> CopyGrowGuard {
        core::ptr::addr_of_mut!(COPY_GROW_CALLS).write(0);
        core::ptr::addr_of_mut!(COPY_GROW_RECEIVER).write(core::ptr::null_mut());
        core::ptr::addr_of_mut!(COPY_GROW_ADDITIONAL).write(0);
        core::ptr::addr_of_mut!(COPY_DESTINATION_STORAGE).write(destination_storage);
        core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_GROW).write_volatile(record_copy_grow);
        CopyGrowGuard
    }

    #[test]
    fn copy_construction_grows_then_copies_zero_one_and_many_elements() {
        const WORDS_PER_BUFFER: usize = 16;
        let _lock = COPY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slab = match crate::testing::try_map_u32_slab(
            crate::testing::hints::OBSERVABLE_ARRAY_COPY_CONSTRUCT,
            WORDS_PER_BUFFER * 2 * core::mem::size_of::<u32>(),
        ) {
            Some(slab) => slab,
            None => {
                crate::testing::note_missing_u32_fixture("cxx::observable_array");
                return;
            }
        };
        let source_words = slab.cast::<u32>();
        let destination_words = unsafe { source_words.add(WORDS_PER_BUFFER) };
        let source_storage = source_words as usize as u32;
        let destination_storage = destination_words as usize as u32;

        for count in [0u32, 1, 5] {
            let mut destination = GuardedStorage::poisoned();
            let destination_object = destination.object();
            unsafe {
                for index in 0..WORDS_PER_BUFFER {
                    source_words.add(index).write_volatile(0x1000_0000 + index as u32);
                    destination_words.add(index).write_volatile(0x5a5a_5a5a);
                }
            }
            let source = ObservableArray {
                base: FrameworkObject { vtable: 0xfeed_face },
                len: count,
                storage: source_storage,
                observers: 0xc001_c0de,
            };
            let _grow = unsafe { install_copy_grow(destination_storage) };

            let returned = unsafe { observable_array_copy_construct(destination_object, &source) };

            assert_eq!(returned, destination_object, "the copy constructor returns destination in r0");
            assert_eq!(unsafe { COPY_GROW_CALLS }, 1, "every count, including zero, reaches growth");
            assert_eq!(unsafe { COPY_GROW_RECEIVER }, destination_object);
            assert_eq!(unsafe { COPY_GROW_ADDITIONAL }, count as i32);
            assert_eq!(
                destination.words,
                [0xa5a5_a5a5, OBSERVABLE_ARRAY_VTABLE, count, destination_storage, 0, 0xa5a5_a5a5],
                "only the target fields are initialized; source observers never transfer"
            );
            unsafe {
                for index in 0..WORDS_PER_BUFFER {
                    assert_eq!(
                        source_words.add(index).read_volatile(),
                        0x1000_0000 + index as u32,
                        "copying leaves source storage intact"
                    );
                    let expected = if index < count as usize {
                        0x1000_0000 + index as u32
                    } else {
                        0x5a5a_5a5a
                    };
                    assert_eq!(
                        destination_words.add(index).read_volatile(),
                        expected,
                        "the byte count is exactly source count times four"
                    );
                }
            }
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

    #[test]
    fn clear_dispatches_the_wrapping_negative_of_each_length() {
        let _lock = CLEAR_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        for (len, expected_delta) in [
            (0, 0),
            (1, -1),
            (0x7fff_ffff, -0x7fff_ffff),
            (0x8000_0000, i32::MIN),
            (0xffff_ffff, 1),
        ] {
            let mut array = ObservableArrayClearHost { vtable: &CLEAR_VTABLE, len };
            let object = core::ptr::addr_of_mut!(array).cast::<ObservableArray>();

            unsafe {
                reset_clear_recording();
                observable_array_clear(object);

                assert_eq!(core::ptr::addr_of!(CLEAR_CALLS).read(), 1, "one virtual call for len {len:#010x}");
                assert_eq!(core::ptr::addr_of!(CLEAR_RECEIVER).read(), object);
                assert_eq!(core::ptr::addr_of!(CLEAR_DELTA).read(), expected_delta);
            }
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
        // Its own hint: the drain test above already holds OBSERVABLE_ARRAY
        // for the life of the process, and a shared hint would send this
        // mapping above 4 GiB and skip the one test that proves the wired
        // default terminates.
        let slab = match crate::testing::try_map_u32_slab(
            crate::testing::hints::OBSERVABLE_ARRAY_DRAIN,
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

    // --- append @ 0x0827196c --------------------------------------------

    #[derive(Debug, PartialEq, Eq)]
    enum AppendStep {
        IsDeferred,
        Deferred { sentinel: i32, element: usize },
        Resize { delta: i32 },
        Write { index: u32, element: usize },
        Notify { index: u32 },
        Finish { reason: u32 },
    }

    static APPEND_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static APPEND_TRACE: parking_lot::Mutex<Vec<AppendStep>> = parking_lot::Mutex::new(Vec::new());
    static mut APPEND_DEFERRED: u32 = 0;
    static mut APPEND_DEFERRED_RETURN: u32 = 0;

    unsafe extern "C" fn record_append_is_deferred(_this: *mut ObservableArray) -> u32 {
        APPEND_TRACE.lock().push(AppendStep::IsDeferred);
        core::ptr::addr_of!(APPEND_DEFERRED).read()
    }

    unsafe extern "C" fn record_append_deferred(
        _this: *mut ObservableArray,
        sentinel: i32,
        element: *mut u8,
    ) -> u32 {
        APPEND_TRACE.lock().push(AppendStep::Deferred {
            sentinel,
            element: element as usize,
        });
        core::ptr::addr_of!(APPEND_DEFERRED_RETURN).read()
    }

    unsafe extern "C" fn record_append_resize(_this: *mut ObservableArray, delta: i32) {
        APPEND_TRACE.lock().push(AppendStep::Resize { delta });
    }

    unsafe extern "C" fn record_append_write(
        _this: *mut ObservableArray,
        index: u32,
        element: *mut u8,
    ) {
        APPEND_TRACE.lock().push(AppendStep::Write {
            index,
            element: element as usize,
        });
    }

    unsafe extern "C" fn record_append_finish(_this: *mut ObservableArray, reason: u32) {
        APPEND_TRACE.lock().push(AppendStep::Finish { reason });
    }

    unsafe extern "C" fn record_append_notify(_this: *mut ObservableArray, index: u32) {
        APPEND_TRACE.lock().push(AppendStep::Notify { index });
    }

    static APPEND_VTABLE: ObservableArrayAppendVtable = ObservableArrayAppendVtable {
        unresolved_00_1c: [0; 8],
        append_deferred: record_append_deferred,
        unresolved_24_5c: [0; 15],
        append_is_deferred: record_append_is_deferred,
        unresolved_64_84: [0; 9],
        append_finish: record_append_finish,
        unresolved_8c_a4: [0; 7],
        append_write: record_append_write,
        unresolved_ac_b8: [0; 4],
        append_resize: record_append_resize,
    };

    struct AppendSeamGuard;
    impl Drop for AppendSeamGuard {
        fn drop(&mut self) {
            unsafe {
                #[cfg(target_os = "none")]
                core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_NOTIFY_APPEND)
                    .write_volatile(firmware_observable_array_notify_append);
                #[cfg(not(target_os = "none"))]
                core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_NOTIFY_APPEND)
                    .write_volatile(missing_observable_array_notify_append);
            }
        }
    }

    fn install_append_recorder(deferred: u32, deferred_return: u32) -> AppendSeamGuard {
        unsafe {
            core::ptr::addr_of_mut!(APPEND_DEFERRED).write(deferred);
            core::ptr::addr_of_mut!(APPEND_DEFERRED_RETURN).write(deferred_return);
            core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_NOTIFY_APPEND)
                .write_volatile(record_append_notify);
        }
        APPEND_TRACE.lock().clear();
        AppendSeamGuard
    }

    fn append_trace() -> Vec<AppendStep> {
        core::mem::take(&mut *APPEND_TRACE.lock())
    }

    #[test]
    fn append_grows_writes_notifies_and_finishes_at_the_old_index() {
        let _lock = APPEND_LOCK.lock();
        let _seam = install_append_recorder(0, 0);
        let mut array = ObservableArrayAppendHost {
            vtable: &APPEND_VTABLE,
            len: 0xffff_ffff,
        };
        let mut element = 0xdead_beefu32;
        let object = core::ptr::addr_of_mut!(array).cast::<ObservableArray>();

        let returned = unsafe { observable_array_append(object, core::ptr::addr_of_mut!(element).cast()) };

        assert_eq!(returned, 0xffff_ffff, "r0 is the length sampled before growth");
        assert_eq!(array.len, 0xffff_ffff, "only the virtual resize operation can change len");
        assert_eq!(
            append_trace(),
            [
                AppendStep::IsDeferred,
                AppendStep::Resize { delta: 1 },
                AppendStep::Write { index: 0xffff_ffff, element: core::ptr::addr_of_mut!(element) as usize },
                AppendStep::Notify { index: 0xffff_ffff },
                AppendStep::Finish { reason: 0 },
            ],
            "the raw blx/bl/blx order is probe, resize, write, notify, finish"
        );
    }

    #[test]
    fn a_deferred_append_uses_the_sentinel_and_skips_the_immediate_path() {
        let _lock = APPEND_LOCK.lock();
        let _seam = install_append_recorder(1, 0x1234_5678);
        let mut array = ObservableArrayAppendHost {
            vtable: &APPEND_VTABLE,
            len: 0,
        };
        let mut element = 0;
        let object = core::ptr::addr_of_mut!(array).cast::<ObservableArray>();

        let returned = unsafe { observable_array_append(object, core::ptr::addr_of_mut!(element).cast()) };

        assert_eq!(returned, 0x1234_5678, "the deferred vtable result propagates unchanged");
        assert_eq!(array.len, 0, "the wrapper does not resize before a deferred append");
        assert_eq!(
            append_trace(),
            [
                AppendStep::IsDeferred,
                AppendStep::Deferred {
                    sentinel: 0x7fff_ffff,
                    element: core::ptr::addr_of_mut!(element) as usize,
                },
            ],
            "the `bxne r3` path bypasses resize, write, observer broadcast, and finish"
        );
    }
}
