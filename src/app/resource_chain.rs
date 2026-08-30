//! `resource_chain_find` — original: `FUN_0827216c` @ 0x0827216c
//! (84 bytes; **377 `bl` + 11 `b` call sites**, binary-scanned over the
//! whole decrypted image — the most-called function in retailOS that had
//! not been ported).
//!
//! The framework's typed **resource lookup**: walk a chain of resource
//! providers and ask each one, through its vtable, for the resource
//! named by a (four-character kind, numeric id) pair. The first provider
//! that answers wins; its answer is a raw pointer the caller casts to
//! whatever the kind implies.
//!
//! ```text
//! 0827216c  push {r3, r4, r5, r6, r7, lr}  @ r3 push = the out word
//! 08272170  mov  r5, r1                    @ kind
//! 08272174  mov  r1, #0
//! 08272178  mov  r6, r2                    @ id
//! 0827217c  mov  r4, r0                    @ node = head
//! 08272180  str  r1, [sp]                  @ found = NULL   (once)
//! 08272184  b    0x82721b0                 @ enter at the test
//! 08272188  ldr  r0, [r4]                  @ vtable = node->vtable
//! 0827218c  mov  r3, sp                    @ &found
//! 08272190  ldr  ip, [r0, #0x64]           @ slot +0x64
//! 08272194  mov  r0, r4
//! 08272198  mov  r2, r6
//! 0827219c  mov  r1, r5
//! 082721a0  blx  ip                        @ node->find(node, kind, id, &found)
//! 082721a4  cmp  r0, #0
//! 082721a8  bne  0x82721b8                 @ answered -> stop
//! 082721ac  ldr  r4, [r4, #0x14]           @ node = node->next
//! 082721b0  cmp  r4, #0
//! 082721b4  bne  0x8272188
//! 082721b8  ldr  r0, [sp]                  @ return found
//! 082721bc  pop  {r3, r4, r5, r6, r7, pc}
//! ```
//!
//! Two details are load-bearing and are reproduced exactly: the out word
//! is cleared **once**, before the loop, so a provider that writes it and
//! then reports "not mine" leaves its write visible in the result; and
//! the provider's `r0` is a plain non-zero test, not a comparison with 1.
//!
//! ## How the class was identified
//!
//! Two constant-binding thunks sit right after the function and are its
//! only shape-revealing callers:
//!
//! ```text
//! 0827238c  mov r2, r1; ldr r1, [pc]; b 0x0827216c   @ literal 0x424d6170 = "BMap"
//! 0827239c  mov r2, r1; ldr r1, [pc]; b 0x0827216c   @ literal 0x53747220 = "Str "
//! ```
//!
//! so `r1` is a FourCC-style type tag stored big-endian in a word, and
//! the caller's second argument is the resource id. The "Str " thunk's
//! result is consumed as a `const char *`: at 0x080c6324 it is handed
//! straight to the string-object constructor @ 0x0827735c (the class
//! whose vtable literal is 0x089a6044 — see `cxx/string_object.rs`),
//! and the 0x080d28e0 cluster copies it with the bounded UTF-8 copy
//! @ 0x08275d00 into 0x20-byte fields. So kind "Str " resolves to a
//! NUL-terminated C string and kind "BMap" to a bitmap.
//!
//! The chain head is task-local: the 17-call-site wrapper @ 0x08272360
//! is `head = task_ctx_field_0x30(); if (head) return
//! resource_chain_find(head, kind, id);` — i.e. field +0x30 of the
//! current task's context block (ported in `util/context_field.rs`) is
//! the head of this provider chain. The `next` link at +0x14 is
//! refcounted: its setter @ 0x082722a0 releases the old link and
//! retains the new one.
//!
//! ## Deviations
//!
//! - The provider object and its vtable are modeled as `#[repr(C)]`
//!   structs with real Rust pointers, so the field offsets are the
//!   original's on the 32-bit target (`vtable` +0x00, `next` +0x14,
//!   slot +0x64 = the 26th vtable word) and are self-consistent on the
//!   64-bit host, where the tests build the graph natively.
//! - The original's slot load is unguarded: a provider with a NULL
//!   vtable or a NULL slot faults. The port keeps the unguarded load
//!   (a NULL `head` is the loop's own exit test, exactly as in the
//!   original, and is *not* a fault).
//! - `resource_chain_find_string` and `resource_chain_find_bitmap` are
//!   calls here, where the originals @ 0x0827239c and 0x0827238c are
//!   tail `b`s; the observable behavior is identical.

use core::ptr;

/// A resource type tag: four characters packed big-endian into a word,
/// the way the image's literal pool stores them (0x53747220 = `"Str "`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct ResourceKind(pub u32);

impl ResourceKind {
    /// `"Str "` — literal @ 0x082723a8, bound by the thunk @ 0x0827239c.
    /// Resolves to a NUL-terminated C string.
    pub const STRING: ResourceKind = ResourceKind(0x5374_7220);

    /// `"BMap"` — literal @ 0x08272398, bound by the thunk @ 0x0827238c.
    pub const BITMAP: ResourceKind = ResourceKind(0x424d_6170);
}

/// Vtable slot +0x64: "do you own this resource?".
///
/// Returns non-zero when the provider answered, in which case it has
/// written the resource pointer through `found`.
pub type ResourceFindFn = unsafe extern "C" fn(
    provider: *mut ResourceProvider,
    kind: ResourceKind,
    id: u32,
    found: *mut *mut u8,
) -> u32;

/// Vtable slot +0x58: "read the entry back".
///
/// Invoked on the provider that accepted a write (see
/// [`resource_chain_write`]); the result is that function's return
/// value. Only (kind, id) are passed — the written value is not.
pub type ResourceReadFn = unsafe extern "C" fn(
    provider: *mut ResourceProvider,
    kind: ResourceKind,
    id: u32,
) -> u32;

/// Vtable slot +0x68: "take this write".
///
/// Returns non-zero when the provider accepted the write of `value`
/// (with `flags`) to the entry `(kind, id)`.
pub type ResourceWriteFn = unsafe extern "C" fn(
    provider: *mut ResourceProvider,
    kind: ResourceKind,
    id: u32,
    value: u32,
    flags: u32,
) -> u32;

/// The provider vtable. Only slots +0x58, +0x64 and +0x68 are decoded;
/// the words around them are named as blocks so that the decoded slots
/// land on their original offsets on the 32-bit target without any
/// literal byte offset.
#[repr(C)]
pub struct ResourceProviderVTable {
    /// Slots +0x00..+0x54, not decoded by this port.
    pub slots_below: [Option<unsafe extern "C" fn()>; 22],
    /// Slot +0x58.
    pub read: ResourceReadFn,
    /// Slots +0x5c..+0x60, not decoded by this port.
    pub slots_between: [Option<unsafe extern "C" fn()>; 2],
    /// Slot +0x64.
    pub find: ResourceFindFn,
    /// Slot +0x68.
    pub write: ResourceWriteFn,
}

/// A node of the provider chain. Only the vtable pointer and the `next`
/// link are decoded; the four words between them belong to the class's
/// unported state.
#[repr(C)]
pub struct ResourceProvider {
    /// +0x00
    pub vtable: *const ResourceProviderVTable,
    /// +0x04..+0x10, not decoded by this port.
    pub state_below_next: [*mut u8; 4],
    /// +0x14 — the next provider to try, refcounted by the setter
    /// @ 0x082722a0.
    pub next: *mut ResourceProvider,
}

/// resource_chain_find — original: `FUN_0827216c` @ 0x0827216c
/// (84 bytes).
///
/// Asks each provider from `head` along the `next` chain for the
/// resource `(kind, id)` and returns the first answer. Returns NULL for
/// an empty chain, or when no provider answers and none wrote the out
/// word (see the module header: the word is cleared once, not per node).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resource_chain_find(
    head: *mut ResourceProvider,
    kind: ResourceKind,
    id: u32,
) -> *mut u8 {
    let mut found: *mut u8 = ptr::null_mut();
    let mut node = head;
    while !node.is_null() {
        let find = (*(*node).vtable).find;
        if find(node, kind, id, &mut found) != 0 {
            break;
        }
        node = (*node).next;
    }
    found
}

/// resource_chain_write — original: `FUN_08272230` @ 0x08272230
/// (112 bytes; **28 `bl` + 2 `blne` call sites**, binary-scanned over
/// the whole decrypted image by decoding every B/BL word — Ghidra's
/// "30" is the sum; the predicated pair @ 0x0813427c and 0x0816b380
/// gates the call on a caller-side condition. No DATA word in the
/// image holds 0x08272230, so it is never dispatched virtually).
///
/// The write variant of [`resource_chain_find`]: offer the entry
/// `(kind, id)` a new `value` (with `flags`) down the provider chain
/// through vtable slot +0x68; the first provider that accepts is then
/// asked through slot +0x58 for the entry's value, and that answer is
/// the return. Returns 0 when no provider accepts.
///
/// ```text
/// 08272230  push {r3, r4, r5, r6, r7, r8, r9, lr}  @ r3 push = the stack-arg word
/// 08272234  ldr  r8, [sp, #32]     @ flags (5th argument, passed on the stack)
/// 08272238  mov  r7, r3            @ value
/// 0827223c  mov  r6, r2            @ id
/// 08272240  mov  r5, r1            @ kind
/// 08272244  mov  r4, r0            @ node = head
/// 08272248  str  r8, [sp]          @ stack arg for the slot call (once)
/// 0827224c  ldr  r0, [r4]          @ vtable = node->vtable   <- loop top
/// 08272250  mov  r3, r7
/// 08272254  ldr  ip, [r0, #0x68]   @ slot +0x68
/// 08272258  mov  r0, r4
/// 0827225c  mov  r2, r6
/// 08272260  mov  r1, r5
/// 08272264  blx  ip                @ node->write(node, kind, id, value, flags)
/// 08272268  cmp  r0, #0
/// 0827226c  ldreq r4, [r4, #0x14]  @ declined: node = node->next
/// 08272270  beq  0x8272294
/// 08272274  ldr  r0, [r4]          @ accepted: tail-call slot +0x58
/// 08272278  mov  r2, r6
/// 0827227c  ldr  r3, [r0, #0x58]
/// 08272280  add  sp, sp, #4
/// 08272284  mov  r0, r4
/// 08272288  mov  r1, r5
/// 0827228c  pop  {r4, r5, r6, r7, r8, r9, lr}
/// 08272290  bx   r3                @ return node->read(node, kind, id)
/// 08272294  cmp  r4, #0
/// 08272298  bne  0x827224c
/// 0827229c  pop  {r3, r4, r5, r6, r7, r8, r9, pc}  @ r0 = 0: nobody took it
/// ```
///
/// Three details are load-bearing and are reproduced exactly. First,
/// unlike the find sibling, entry falls INTO the loop body — the NULL
/// test guards only the `next` link, so a NULL `head` faults on the
/// vtable load; the port keeps the unguarded first dereference (and the
/// unguarded slot loads). Second, the accept test is a plain non-zero
/// test (`cmp r0, #0` / `ldreq`/`beq`), not a comparison with 1. Third,
/// the accepting provider is asked through slot +0x58 with only
/// `(kind, id)` — `value` and `flags` are not forwarded — and that
/// result is returned verbatim, including 0.
///
/// ## How it was identified
///
/// The setter-side caller @ 0x0825b734 (disassembled from raw bytes)
/// stores 4 on the stack as the fifth argument and calls with
/// (kind `"Ui32"` @ 0x0825b7b0, id 0x60a4 @ 0x0825b7ac, the new value,
/// 4) on the class-0x6000 singleton's provider chain — the write-side
/// sibling of the ported `class6000_ui32_resource_60a4` getter, which
/// reads the same (kind, id) pair through [`resource_chain_find`].
/// Other callers (e.g. @ 0x081407b0, @ 0x0816b208) pass `flags` 4 or 0
/// and ignore the return. The fifth argument sits on the stack per the
/// AAPCS; a five-argument `extern "C"` signature reproduces that
/// exactly.
///
/// Deviation: the original tail-branches into slot +0x58 (`bx r3`);
/// the port calls it and returns the result — observationally identical.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resource_chain_write(
    head: *mut ResourceProvider,
    kind: ResourceKind,
    id: u32,
    value: u32,
    flags: u32,
) -> u32 {
    let mut node = head;
    loop {
        let vtable = (*node).vtable;
        if ((*vtable).write)(node, kind, id, value, flags) != 0 {
            return ((*vtable).read)(node, kind, id);
        }
        node = (*node).next;
        if node.is_null() {
            return 0;
        }
    }
}

/// resource_chain_find_bitmap — original: `FUN_0827238c` @ 0x0827238c
/// (16 bytes: 12 code + the 4-byte `"BMap"` literal @ 0x08272398;
/// **46 `bl` + 2 `b` call sites**, binary-scanned by decoding every
/// B/BL word in osos.dec — all 46 `bl` unconditional, the two `b` are
/// tail calls @ 0x081eb070 and 0x081ed150. No DATA word in the image
/// holds 0x0827238c, so it is never dispatched virtually).
///
/// Binds [`ResourceKind::BITMAP`] as the kind of [`resource_chain_find`]:
/// looks the bitmap resource `id` up in the provider chain and returns
/// the provider's raw pointer to it (NULL when no provider owns it).
///
/// Ghidra sizes this at 12 bytes, dropping the trailing literal word.
/// The real extent runs to 0x0827239c, where the `"Str "` sibling's
/// first instruction begins.
/// The two thunks differ only in the literal they load, so LLVM cannot
/// fold them today — but the explicit `link_section` makes that
/// structural rather than incidental, the way `util/beload.rs` and
/// `cxx/templates.rs` pin their near-identical siblings apart.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_chain_find_bitmap")]
pub unsafe extern "C" fn resource_chain_find_bitmap(
    head: *mut ResourceProvider,
    id: u32,
) -> *mut u8 {
    resource_chain_find(head, ResourceKind::BITMAP, id)
}

/// resource_chain_find_string — original: `FUN_0827239c` @ 0x0827239c
/// (12 bytes: 8 code + the 4-byte `"Str "` literal @ 0x082723a8;
/// 171 `bl` + 14 `b` call sites, binary-scanned).
///
/// Binds [`ResourceKind::STRING`] as the kind of [`resource_chain_find`]:
/// looks the string resource `id` up in the provider chain and returns
/// it as a C string (NULL when no provider owns it).
/// Pinned into its own `link_section` for the reason given on
/// [`resource_chain_find_bitmap`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_chain_find_string")]
pub unsafe extern "C" fn resource_chain_find_string(
    head: *mut ResourceProvider,
    id: u32,
) -> *const u8 {
    resource_chain_find(head, ResourceKind::STRING, id) as *const u8
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// What one scripted provider did when it was asked.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Call {
        provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
    }

    /// Scripted behavior of one provider: what it writes through the out
    /// word (if anything) and what it reports.
    #[derive(Clone, Copy)]
    struct Script {
        writes: Option<*mut u8>,
        answers: u32,
    }

    impl Script {
        /// Reports "not mine" without touching the out word.
        const fn passes() -> Script {
            Script { writes: None, answers: 0 }
        }
        /// Answers with `value`.
        fn answers(value: usize) -> Script {
            Script { writes: Some(value as *mut u8), answers: 1 }
        }
    }

    // The recorder is process-global because the callback is a plain
    // `extern "C"` function pointer, exactly like the original's slot;
    // the tests in this module run under one lock.
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: Vec<Call> = Vec::new();
    static mut SCRIPTS: Vec<Script> = Vec::new();

    /// The scripted vtable slot +0x64: records the call, then acts out
    /// the script for its position in the chain.
    unsafe extern "C" fn scripted_find(
        provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
        found: *mut *mut u8,
    ) -> u32 {
        let index = CALLS.len();
        CALLS.push(Call { provider, kind, id });
        let script = SCRIPTS[index];
        if let Some(value) = script.writes {
            *found = value;
        }
        script.answers
    }

    /// The find tests never dispatch the write-path slots; these stubs
    /// only fill the vtable.
    unsafe extern "C" fn read_not_called(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
    ) -> u32 {
        0
    }
    unsafe extern "C" fn write_not_called(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        _value: u32,
        _flags: u32,
    ) -> u32 {
        0
    }

    const VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22],
        read: read_not_called,
        slots_between: [None; 2],
        find: scripted_find,
        write: write_not_called,
    };

    /// A chain of `scripts.len()` providers, each running the script at
    /// its own position. Boxed so the node addresses are stable and
    /// distinguishable in the recording.
    struct Chain {
        nodes: Vec<std::boxed::Box<ResourceProvider>>,
    }

    impl Chain {
        fn new(scripts: &[Script]) -> Chain {
            unsafe {
                CALLS = Vec::new();
                SCRIPTS = scripts.to_vec();
            }
            let mut nodes: Vec<std::boxed::Box<ResourceProvider>> = (0..scripts.len())
                .map(|_| {
                    std::boxed::Box::new(ResourceProvider {
                        vtable: &VTABLE,
                        state_below_next: [ptr::null_mut(); 4],
                        next: ptr::null_mut(),
                    })
                })
                .collect();
            for i in (1..nodes.len()).rev() {
                let next = &mut *nodes[i] as *mut ResourceProvider;
                nodes[i - 1].next = next;
            }
            Chain { nodes }
        }

        fn head(&mut self) -> *mut ResourceProvider {
            match self.nodes.first_mut() {
                Some(node) => &mut **node as *mut ResourceProvider,
                None => ptr::null_mut(),
            }
        }

        fn node(&mut self, index: usize) -> *mut ResourceProvider {
            &mut *self.nodes[index] as *mut ResourceProvider
        }

        fn calls(&self) -> Vec<Call> {
            unsafe { CALLS.clone() }
        }
    }

    #[test]
    fn empty_chain_returns_null_without_asking_anyone() {
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[]);
        let head = chain.head();
        assert!(unsafe { resource_chain_find(head, ResourceKind::STRING, 7) }.is_null());
        assert!(chain.calls().is_empty());
    }

    #[test]
    fn stops_at_the_first_provider_that_answers() {
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[Script::answers(0xabc), Script::answers(0xdef)]);
        let head = chain.head();

        let found = unsafe { resource_chain_find(head, ResourceKind::BITMAP, 3) };

        assert_eq!(found as usize, 0xabc);
        assert_eq!(chain.calls().len(), 1, "the second provider is never asked");
    }

    #[test]
    fn walks_the_chain_in_order_forwarding_kind_and_id_verbatim() {
        let _lock = TEST_LOCK.lock();
        let mut chain =
            Chain::new(&[Script::passes(), Script::passes(), Script::answers(0x1234)]);
        let head = chain.head();

        let found = unsafe { resource_chain_find(head, ResourceKind(0xdead_beef), 0x8000_0001) };

        assert_eq!(found as usize, 0x1234);
        let expected: Vec<Call> = (0..3)
            .map(|i| Call {
                provider: chain.node(i),
                kind: ResourceKind(0xdead_beef),
                id: 0x8000_0001,
            })
            .collect();
        assert_eq!(chain.calls(), expected);
    }

    #[test]
    fn nobody_answers_returns_null_after_asking_everyone() {
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[Script::passes(), Script::passes()]);
        let head = chain.head();

        assert!(unsafe { resource_chain_find(head, ResourceKind::STRING, 1) }.is_null());
        assert_eq!(chain.calls().len(), 2);
    }

    #[test]
    fn a_write_from_a_provider_that_declines_survives_to_the_result() {
        let _lock = TEST_LOCK.lock();
        // The out word is cleared once, before the loop — so a provider
        // that fills it in and then reports "not mine" still decides the
        // result when nobody else answers. This is the original's
        // behavior, not a convenience.
        let mut chain = Chain::new(&[
            Script { writes: Some(0x5555 as *mut u8), answers: 0 },
            Script::passes(),
        ]);
        let head = chain.head();

        let found = unsafe { resource_chain_find(head, ResourceKind::STRING, 1) };

        assert_eq!(found as usize, 0x5555, "the declining provider's write is not undone");
    }

    #[test]
    fn an_answer_without_a_write_yields_null() {
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[Script { writes: None, answers: 1 }, Script::answers(9)]);
        let head = chain.head();

        assert!(unsafe { resource_chain_find(head, ResourceKind::STRING, 1) }.is_null());
        assert_eq!(chain.calls().len(), 1, "the answer still stops the walk");
    }

    #[test]
    fn any_nonzero_answer_stops_the_walk() {
        let _lock = TEST_LOCK.lock();
        // `cmp r0, #0; bne` — not a comparison with 1.
        for answers in [1u32, 2, 0x8000_0000, u32::MAX] {
            let mut chain = Chain::new(&[
                Script { writes: Some(0x77 as *mut u8), answers },
                Script::answers(0x88),
            ]);
            let head = chain.head();

            let found = unsafe { resource_chain_find(head, ResourceKind::STRING, 0) };

            assert_eq!(found as usize, 0x77, "answer {answers:#x} must stop the walk");
            assert_eq!(chain.calls().len(), 1);
        }
    }

    #[test]
    fn each_providers_own_vtable_is_used() {
        let _lock = TEST_LOCK.lock();
        // The slot is re-loaded from `node->vtable` every iteration, so a
        // chain of mixed classes dispatches per node. A second vtable
        // whose slot answers immediately proves the reload.
        unsafe extern "C" fn always_answers(
            _provider: *mut ResourceProvider,
            _kind: ResourceKind,
            _id: u32,
            found: *mut *mut u8,
        ) -> u32 {
            *found = 0x4242 as *mut u8;
            1
        }
        static OTHER: ResourceProviderVTable = ResourceProviderVTable {
            slots_below: [None; 22],
            read: read_not_called,
            slots_between: [None; 2],
            find: always_answers,
            write: write_not_called,
        };

        let mut chain = Chain::new(&[Script::passes(), Script::passes()]);
        chain.nodes[1].vtable = &OTHER;
        let head = chain.head();

        let found = unsafe { resource_chain_find(head, ResourceKind::STRING, 0) };

        assert_eq!(found as usize, 0x4242);
        assert_eq!(chain.calls().len(), 1, "only the first node ran the scripted slot");
    }

    #[test]
    fn string_thunk_binds_the_str_kind_and_forwards_the_id() {
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[Script::answers(0xc0de)]);
        let head = chain.head();

        let found = unsafe { resource_chain_find_string(head, 0x1122_3344) };

        assert_eq!(found as usize, 0xc0de);
        assert_eq!(
            chain.calls(),
            [Call { provider: chain.node(0), kind: ResourceKind::STRING, id: 0x1122_3344 }]
        );
    }

    #[test]
    fn string_thunk_on_an_empty_chain_returns_null() {
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[]);
        let head = chain.head();
        assert!(unsafe { resource_chain_find_string(head, 5) }.is_null());
    }

    #[test]
    fn bitmap_thunk_binds_the_bmap_kind_and_forwards_the_id() {
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[Script::answers(0xb17a)]);
        let head = chain.head();

        let found = unsafe { resource_chain_find_bitmap(head, 0x1122_3344) };

        assert_eq!(found as usize, 0xb17a);
        assert_eq!(
            chain.calls(),
            [Call { provider: chain.node(0), kind: ResourceKind::BITMAP, id: 0x1122_3344 }]
        );
    }

    #[test]
    fn bitmap_thunk_on_an_empty_chain_returns_null() {
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[]);
        let head = chain.head();
        assert!(unsafe { resource_chain_find_bitmap(head, 5) }.is_null());
    }

    #[test]
    fn the_two_thunks_bind_different_kinds() {
        // The only difference between 0x0827238c and 0x0827239c is the
        // literal they load into r1; a build that folded the two bodies
        // onto one symbol would show up right here.
        let _lock = TEST_LOCK.lock();
        let mut chain = Chain::new(&[Script::passes(), Script::passes()]);
        let head = chain.head();

        unsafe { resource_chain_find_bitmap(head, 1) };
        let bitmap_kinds: Vec<ResourceKind> = chain.calls().iter().map(|c| c.kind).collect();

        let mut chain = Chain::new(&[Script::passes(), Script::passes()]);
        let head = chain.head();
        unsafe { resource_chain_find_string(head, 1) };
        let string_kinds: Vec<ResourceKind> = chain.calls().iter().map(|c| c.kind).collect();

        assert_eq!(bitmap_kinds, [ResourceKind::BITMAP; 2]);
        assert_eq!(string_kinds, [ResourceKind::STRING; 2]);
        assert_ne!(ResourceKind::BITMAP, ResourceKind::STRING);
    }

    #[test]
    fn kind_literals_spell_their_four_characters_big_endian() {
        assert_eq!(&ResourceKind::STRING.0.to_be_bytes(), b"Str ");
        assert_eq!(&ResourceKind::BITMAP.0.to_be_bytes(), b"BMap");
    }

    // ---- resource_chain_write harness -----------------------------

    /// What one scripted provider saw when it was offered a write.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct WriteCall {
        provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
        value: u32,
        flags: u32,
    }

    /// What the read-back slot saw on the accepting provider.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct ReadCall {
        provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
    }

    /// Scripted behavior of one provider on the write path: whether it
    /// accepts the write, and (when it does) what its read-back slot
    /// returns.
    #[derive(Clone, Copy)]
    struct WriteScript {
        accepts: u32,
        read_result: u32,
    }

    impl WriteScript {
        /// Declines the write.
        const fn declines() -> WriteScript {
            WriteScript { accepts: 0, read_result: 0 }
        }
        /// Accepts the write; the read-back returns `read_result`.
        const fn accepts(accepts: u32, read_result: u32) -> WriteScript {
            WriteScript { accepts, read_result }
        }
    }

    static mut WRITE_CALLS: Vec<WriteCall> = Vec::new();
    static mut READ_CALLS: Vec<ReadCall> = Vec::new();
    static mut WRITE_SCRIPTS: Vec<WriteScript> = Vec::new();

    /// The write tests never dispatch slot +0x64; this stub only fills
    /// the vtable.
    unsafe extern "C" fn find_not_called(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        _found: *mut *mut u8,
    ) -> u32 {
        0
    }

    /// The scripted vtable slot +0x68: records the offer, then accepts
    /// or declines per the script for its position in the chain.
    unsafe extern "C" fn scripted_write(
        provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
        value: u32,
        flags: u32,
    ) -> u32 {
        let index = WRITE_CALLS.len();
        WRITE_CALLS.push(WriteCall { provider, kind, id, value, flags });
        WRITE_SCRIPTS[index].accepts
    }

    /// The scripted vtable slot +0x58: records the read-back and
    /// returns the script's result for the provider that accepted.
    unsafe extern "C" fn scripted_read(
        provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
    ) -> u32 {
        READ_CALLS.push(ReadCall { provider, kind, id });
        // The read runs on the provider whose write accepted; its
        // script sits at the last write call's position.
        WRITE_SCRIPTS[WRITE_CALLS.len() - 1].read_result
    }

    const WRITE_VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22],
        read: scripted_read,
        slots_between: [None; 2],
        find: find_not_called,
        write: scripted_write,
    };

    /// A chain of write-path providers, each running the script at its
    /// own position. Boxed so the node addresses are stable.
    struct WriteChain {
        nodes: Vec<std::boxed::Box<ResourceProvider>>,
    }

    impl WriteChain {
        fn new(scripts: &[WriteScript]) -> WriteChain {
            unsafe {
                WRITE_CALLS = Vec::new();
                READ_CALLS = Vec::new();
                WRITE_SCRIPTS = scripts.to_vec();
            }
            let mut nodes: Vec<std::boxed::Box<ResourceProvider>> = (0..scripts.len())
                .map(|_| {
                    std::boxed::Box::new(ResourceProvider {
                        vtable: &WRITE_VTABLE,
                        state_below_next: [ptr::null_mut(); 4],
                        next: ptr::null_mut(),
                    })
                })
                .collect();
            for i in (1..nodes.len()).rev() {
                let next = &mut *nodes[i] as *mut ResourceProvider;
                nodes[i - 1].next = next;
            }
            WriteChain { nodes }
        }

        fn head(&mut self) -> *mut ResourceProvider {
            match self.nodes.first_mut() {
                Some(node) => &mut **node as *mut ResourceProvider,
                None => ptr::null_mut(),
            }
        }

        fn node(&mut self, index: usize) -> *mut ResourceProvider {
            &mut *self.nodes[index] as *mut ResourceProvider
        }

        fn write_calls(&self) -> Vec<WriteCall> {
            unsafe { WRITE_CALLS.clone() }
        }

        fn read_calls(&self) -> Vec<ReadCall> {
            unsafe { READ_CALLS.clone() }
        }
    }

    #[test]
    fn write_first_acceptor_is_read_back_and_stops_the_walk() {
        let _lock = TEST_LOCK.lock();
        let mut chain = WriteChain::new(&[
            WriteScript::accepts(1, 0x1234),
            WriteScript::accepts(1, 0x5678),
        ]);
        let head = chain.head();

        let result = unsafe {
            resource_chain_write(head, ResourceKind::BITMAP, 3, 0xdead_beef, 4)
        };

        assert_eq!(result, 0x1234, "the read-back result is the return value");
        assert_eq!(
            chain.write_calls(),
            [WriteCall {
                provider: chain.node(0),
                kind: ResourceKind::BITMAP,
                id: 3,
                value: 0xdead_beef,
                flags: 4,
            }],
            "the second provider is never offered the write"
        );
        assert_eq!(
            chain.read_calls(),
            [ReadCall { provider: chain.node(0), kind: ResourceKind::BITMAP, id: 3 }],
            "the read-back gets (kind, id) only — value and flags are not forwarded"
        );
    }

    #[test]
    fn write_walks_declining_providers_in_order_forwarding_args_verbatim() {
        let _lock = TEST_LOCK.lock();
        let mut chain = WriteChain::new(&[
            WriteScript::declines(),
            WriteScript::declines(),
            WriteScript::accepts(1, 0x77),
        ]);
        let head = chain.head();

        let result = unsafe {
            resource_chain_write(head, ResourceKind(0x5569_3332), 0x8000_0001, 0x60a4, 0)
        };

        assert_eq!(result, 0x77);
        let expected: Vec<WriteCall> = (0..3)
            .map(|i| WriteCall {
                provider: chain.node(i),
                kind: ResourceKind(0x5569_3332),
                id: 0x8000_0001,
                value: 0x60a4,
                flags: 0,
            })
            .collect();
        assert_eq!(chain.write_calls(), expected);
        assert_eq!(
            chain.read_calls(),
            [ReadCall { provider: chain.node(2), kind: ResourceKind(0x5569_3332), id: 0x8000_0001 }]
        );
    }

    #[test]
    fn write_nobody_accepts_returns_zero_and_never_reads_back() {
        let _lock = TEST_LOCK.lock();
        let mut chain = WriteChain::new(&[WriteScript::declines(), WriteScript::declines()]);
        let head = chain.head();

        let result = unsafe { resource_chain_write(head, ResourceKind::STRING, 1, 9, 4) };

        assert_eq!(result, 0);
        assert_eq!(chain.write_calls().len(), 2, "every provider was offered the write");
        assert!(chain.read_calls().is_empty(), "slot +0x58 runs only after an accept");
    }

    #[test]
    fn write_any_nonzero_accept_stops_the_walk() {
        let _lock = TEST_LOCK.lock();
        // `cmp r0, #0; ldreq/beq` — not a comparison with 1.
        for accepts in [1u32, 2, 0x8000_0000, u32::MAX] {
            let mut chain = WriteChain::new(&[
                WriteScript::accepts(accepts, 0x55),
                WriteScript::accepts(1, 0x66),
            ]);
            let head = chain.head();

            let result = unsafe { resource_chain_write(head, ResourceKind::STRING, 0, 0, 0) };

            assert_eq!(result, 0x55, "accept {accepts:#x} must stop the walk");
            assert_eq!(chain.write_calls().len(), 1);
            assert_eq!(chain.read_calls().len(), 1);
        }
    }

    #[test]
    fn write_a_zero_read_back_is_still_the_result() {
        let _lock = TEST_LOCK.lock();
        // The accept already happened, so a 0 from slot +0x58 is the
        // return value — distinguishable from "nobody accepted" only by
        // the read having run.
        let mut chain = WriteChain::new(&[WriteScript::accepts(1, 0)]);
        let head = chain.head();

        let result = unsafe { resource_chain_write(head, ResourceKind::STRING, 1, 2, 4) };

        assert_eq!(result, 0);
        assert_eq!(chain.read_calls().len(), 1, "the read-back ran, so this is not a decline");
    }

    #[test]
    fn write_each_providers_own_vtable_is_used() {
        let _lock = TEST_LOCK.lock();
        // Both slots are re-loaded from `node->vtable` every iteration,
        // so a chain of mixed classes dispatches per node. A second
        // vtable whose write accepts immediately and whose read answers
        // 0x4242 proves the reload of both slots.
        unsafe extern "C" fn always_accepts(
            _provider: *mut ResourceProvider,
            _kind: ResourceKind,
            _id: u32,
            _value: u32,
            _flags: u32,
        ) -> u32 {
            1
        }
        unsafe extern "C" fn answers_0x4242(
            _provider: *mut ResourceProvider,
            _kind: ResourceKind,
            _id: u32,
        ) -> u32 {
            0x4242
        }
        static OTHER_WRITE: ResourceProviderVTable = ResourceProviderVTable {
            slots_below: [None; 22],
            read: answers_0x4242,
            slots_between: [None; 2],
            find: find_not_called,
            write: always_accepts,
        };

        let mut chain = WriteChain::new(&[WriteScript::declines(), WriteScript::declines()]);
        chain.nodes[1].vtable = &OTHER_WRITE;
        let head = chain.head();

        let result = unsafe { resource_chain_write(head, ResourceKind::STRING, 0, 1, 4) };

        assert_eq!(result, 0x4242);
        assert_eq!(chain.write_calls().len(), 1, "only the first node ran the scripted slot");
        assert!(chain.read_calls().is_empty(), "the read-back went through the other vtable");
    }

    #[test]
    fn vtable_slots_land_on_their_original_offsets() {
        // The decoded offsets are 4-byte-word positions in the original;
        // check them in words so the assertion holds on both widths.
        let word = core::mem::size_of::<*const u8>();
        assert_eq!(
            core::mem::offset_of!(ResourceProviderVTable, read),
            0x58 / 4 * word,
            "vtable slot +0x58"
        );
        assert_eq!(
            core::mem::offset_of!(ResourceProviderVTable, find),
            0x64 / 4 * word,
            "vtable slot +0x64"
        );
        assert_eq!(
            core::mem::offset_of!(ResourceProviderVTable, write),
            0x68 / 4 * word,
            "vtable slot +0x68"
        );
        assert_eq!(
            core::mem::offset_of!(ResourceProvider, next),
            0x14 / 4 * word,
            "chain link +0x14"
        );
        assert_eq!(core::mem::offset_of!(ResourceProvider, vtable), 0, "vtable +0x00");
    }
}
