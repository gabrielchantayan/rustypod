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
//! - `resource_chain_find_string` is a call here, where the original's
//!   0x0827239c is a tail `b`; the observable behavior is identical.

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

/// The provider vtable. Only slot +0x64 is decoded; the 25 words below
/// it are named as a block so that `find` lands on +0x64 on the 32-bit
/// target without any literal byte offset.
#[repr(C)]
pub struct ResourceProviderVTable {
    /// Slots +0x00..+0x60, not decoded by this port.
    pub slots_below: [Option<unsafe extern "C" fn()>; 25],
    /// Slot +0x64.
    pub find: ResourceFindFn,
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

/// resource_chain_find_string — original: `FUN_0827239c` @ 0x0827239c
/// (12 bytes: 8 code + the 4-byte `"Str "` literal @ 0x082723a8;
/// 171 `bl` + 14 `b` call sites, binary-scanned).
///
/// Binds [`ResourceKind::STRING`] as the kind of [`resource_chain_find`]:
/// looks the string resource `id` up in the provider chain and returns
/// it as a C string (NULL when no provider owns it).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
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
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
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

    const VTABLE: ResourceProviderVTable =
        ResourceProviderVTable { slots_below: [None; 25], find: scripted_find };

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
        let _lock = TEST_LOCK.lock().unwrap();
        let mut chain = Chain::new(&[]);
        let head = chain.head();
        assert!(unsafe { resource_chain_find(head, ResourceKind::STRING, 7) }.is_null());
        assert!(chain.calls().is_empty());
    }

    #[test]
    fn stops_at_the_first_provider_that_answers() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut chain = Chain::new(&[Script::answers(0xabc), Script::answers(0xdef)]);
        let head = chain.head();

        let found = unsafe { resource_chain_find(head, ResourceKind::BITMAP, 3) };

        assert_eq!(found as usize, 0xabc);
        assert_eq!(chain.calls().len(), 1, "the second provider is never asked");
    }

    #[test]
    fn walks_the_chain_in_order_forwarding_kind_and_id_verbatim() {
        let _lock = TEST_LOCK.lock().unwrap();
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
        let _lock = TEST_LOCK.lock().unwrap();
        let mut chain = Chain::new(&[Script::passes(), Script::passes()]);
        let head = chain.head();

        assert!(unsafe { resource_chain_find(head, ResourceKind::STRING, 1) }.is_null());
        assert_eq!(chain.calls().len(), 2);
    }

    #[test]
    fn a_write_from_a_provider_that_declines_survives_to_the_result() {
        let _lock = TEST_LOCK.lock().unwrap();
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
        let _lock = TEST_LOCK.lock().unwrap();
        let mut chain = Chain::new(&[Script { writes: None, answers: 1 }, Script::answers(9)]);
        let head = chain.head();

        assert!(unsafe { resource_chain_find(head, ResourceKind::STRING, 1) }.is_null());
        assert_eq!(chain.calls().len(), 1, "the answer still stops the walk");
    }

    #[test]
    fn any_nonzero_answer_stops_the_walk() {
        let _lock = TEST_LOCK.lock().unwrap();
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
        let _lock = TEST_LOCK.lock().unwrap();
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
        static OTHER: ResourceProviderVTable =
            ResourceProviderVTable { slots_below: [None; 25], find: always_answers };

        let mut chain = Chain::new(&[Script::passes(), Script::passes()]);
        chain.nodes[1].vtable = &OTHER;
        let head = chain.head();

        let found = unsafe { resource_chain_find(head, ResourceKind::STRING, 0) };

        assert_eq!(found as usize, 0x4242);
        assert_eq!(chain.calls().len(), 1, "only the first node ran the scripted slot");
    }

    #[test]
    fn string_thunk_binds_the_str_kind_and_forwards_the_id() {
        let _lock = TEST_LOCK.lock().unwrap();
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
        let _lock = TEST_LOCK.lock().unwrap();
        let mut chain = Chain::new(&[]);
        let head = chain.head();
        assert!(unsafe { resource_chain_find_string(head, 5) }.is_null());
    }

    #[test]
    fn kind_literals_spell_their_four_characters_big_endian() {
        assert_eq!(&ResourceKind::STRING.0.to_be_bytes(), b"Str ");
        assert_eq!(&ResourceKind::BITMAP.0.to_be_bytes(), b"BMap");
    }

    #[test]
    fn vtable_slot_lands_on_0x64_on_the_32_bit_target() {
        // The decoded offsets are 4-byte-word positions in the original;
        // check them in words so the assertion holds on both widths.
        let word = core::mem::size_of::<*const u8>();
        assert_eq!(
            core::mem::offset_of!(ResourceProviderVTable, find),
            0x64 / 4 * word,
            "vtable slot +0x64"
        );
        assert_eq!(
            core::mem::offset_of!(ResourceProvider, next),
            0x14 / 4 * word,
            "chain link +0x14"
        );
        assert_eq!(core::mem::offset_of!(ResourceProvider, vtable), 0, "vtable +0x00");
    }
}
