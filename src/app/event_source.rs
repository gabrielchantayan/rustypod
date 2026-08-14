//! The 92-byte retailOS event source object: its constructor, its
//! destructor, and its kind byte.
//!
//! [`crate::app::event_list`] ports the lazily-built event tree that lives
//! at +0x38 of this object. This module ports the object's own constructor
//! and destructor and the accessor for its kind byte, so the two together
//! cover the source's whole lifetime seam.
//!
//! # Where the object comes from
//!
//! The factory @ 0x081472b0 is what pins the layout down. Given the view's
//! source registry it queries the application registry (0x0819fe10) for the
//! registry's own id under the ADS key `'SLst'` (0x534c7374 @ 0x0814735c),
//! and for every declaration in the resulting collection it does:
//!
//! ```text
//!     mov  r0, #92          ; operator new(0x5c)  <- the object size
//!     bl   0x082aadd4
//!     ldr  r1, [sp]         ; id          = declaration[0]
//!     and  r2, r1, #255     ; kind        = declaration[1] & 0xff
//!     mov  r3, r4           ; declaration
//!     bl   0x081e0bac       ; <- ported here
//!     str  r6, [r0, #88]    ; source->+0x58 = the owning registry
//!     add  r0, r6, #12      ; registry map, keyed by the same id
//! ```
//!
//! So the constructor's three arguments are the declaration's id word, the
//! low byte of the declaration's second word, and the declaration pointer
//! itself; the caller — not the constructor — fills in +0x58.
//!
//! # Layout
//!
//! | offset | contents |
//! |--------|----------|
//! | +0x00  | vtable pointer, always [`EVENT_SOURCE_VTABLE`] |
//! | +0x04  | declaration pointer (constructor argument 3) |
//! | +0x08  | id / registry lookup value (constructor argument 1) |
//! | +0x0c  | kind byte (constructor argument 2) |
//! | +0x10  | declaration vector: begin / end / capacity |
//! | +0x1c  | 28-byte child collection |
//! | +0x38  | the event tree of [`crate::app::event_list`] |
//! | +0x54  | "event tree is built" flag |
//! | +0x58  | owning source registry |
//! | +0x5c  | end of object |
//!
//! The +0x08 id doubles as the value [`crate::app::event_list`] resolves
//! under `'SEVT'`, which is why that module calls it the primary event.

use crate::app::event_list::{
    CHUNK_BLOCK_OFFSET, CHUNK_CAPACITY_OFFSET, CHUNK_NEXT_OFFSET, EVENT_LIST_BUILT_OFFSET,
    EVENT_LIST_OFFSET, EVENT_SOURCE_EVENT_BEGIN_OFFSET, EVENT_SOURCE_OPTIONAL_EVENT_OFFSET,
    EVENT_SOURCE_PRIMARY_EVENT_OFFSET, TREE_HEADER_OFFSET, TREE_LEFTMOST_OFFSET,
    TREE_POOL_CHUNKS_OFFSET,
};

/// Byte size of the object, from the `operator new(92)` @ 0x081472fc that
/// precedes every heap construction of it.
pub const EVENT_SOURCE_SIZE: usize = 0x5c;

/// The vtable the constructor installs, from its literal pool word at
/// 0x081e0c30 — the word Ghidra drops from the function's extent.
pub const EVENT_SOURCE_VTABLE: u32 = 0x0898_ecb4;

/// Byte offset of the declaration the source was built from.
pub const EVENT_SOURCE_DECLARATION_OFFSET: usize = 0x04;

/// Byte offset of the kind byte returned by [`event_source_kind`].
pub const EVENT_SOURCE_KIND_OFFSET: usize = 0x0c;

/// Byte offset of the 28-byte child collection constructed at +0x1c.
pub const EVENT_SOURCE_CHILDREN_OFFSET: usize = 0x1c;

/// Sub-object constructors the port calls through, all of which return
/// their own `this`. Each is a distinct firmware routine; none is ported.
#[derive(Clone, Copy)]
pub struct EventSourceConstructOps {
    /// Original 0x083e4a7c: zeroes the three words of the declaration
    /// vector at +0x10. Its second argument is the (ignored) allocator.
    pub construct_declaration_vector: unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8,
    /// Original 0x083db10c: builds the empty 28-byte child collection at
    /// +0x1c around a freshly allocated sentinel node (allocator
    /// 0x083b9f4c). Arguments 2 and 3 are the comparator byte — the
    /// constructor copies `*comparator` to collection+0x19 — and the
    /// ignored allocator.
    pub construct_child_collection: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> *mut u8,
    /// Original 0x083db2d4: the same shape for the event tree at +0x38,
    /// with node allocator 0x083c14c8.
    pub construct_event_list: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> *mut u8,
    /// Original 0x081e059c: fills the declaration vector at +0x10 by
    /// resolving the source's id through the application registry under
    /// `'SLyt'`. Only reached for a positive id.
    pub load_declarations: unsafe extern "C" fn(*mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_construct_declaration_vector(
    vector: *mut u8,
    allocator: *mut u8,
) -> *mut u8 {
    let construct: unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(0x083e_4a7cusize) };
    unsafe { construct(vector, allocator) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_construct_child_collection(
    collection: *mut u8,
    comparator: *mut u8,
    allocator: *mut u8,
) -> *mut u8 {
    let construct: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(0x083d_b10cusize) };
    unsafe { construct(collection, comparator, allocator) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_construct_event_list(
    tree: *mut u8,
    comparator: *mut u8,
    allocator: *mut u8,
) -> *mut u8 {
    let construct: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(0x083d_b2d4usize) };
    unsafe { construct(tree, comparator, allocator) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_load_declarations(source: *mut u8) {
    let load: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x081e_059cusize) };
    unsafe { load(source) }
}

/// Host defaults. Every sub-object constructor returns its `this`, which is
/// what the firmware routines do and what the original's pointer chaining
/// depends on; loading declarations is a no-op without a registry.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_declaration_vector(
    vector: *mut u8,
    _allocator: *mut u8,
) -> *mut u8 {
    vector
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_child_collection(
    collection: *mut u8,
    _comparator: *mut u8,
    _allocator: *mut u8,
) -> *mut u8 {
    collection
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_event_list(
    tree: *mut u8,
    _comparator: *mut u8,
    _allocator: *mut u8,
) -> *mut u8 {
    tree
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_load_declarations(_source: *mut u8) {}

/// Active sub-object constructors for [`event_source_construct`]. Host
/// tests replace this table to observe the construction protocol.
#[cfg(target_os = "none")]
pub static mut EVENT_SOURCE_CONSTRUCT_OPS: EventSourceConstructOps = EventSourceConstructOps {
    construct_declaration_vector: firmware_construct_declaration_vector,
    construct_child_collection: firmware_construct_child_collection,
    construct_event_list: firmware_construct_event_list,
    load_declarations: firmware_load_declarations,
};

#[cfg(not(target_os = "none"))]
pub static mut EVENT_SOURCE_CONSTRUCT_OPS: EventSourceConstructOps = EventSourceConstructOps {
    construct_declaration_vector: missing_construct_declaration_vector,
    construct_child_collection: missing_construct_child_collection,
    construct_event_list: missing_construct_event_list,
    load_declarations: missing_load_declarations,
};

#[inline(always)]
unsafe fn construct_ops() -> EventSourceConstructOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_SOURCE_CONSTRUCT_OPS)) }
}

/// event_source_kind — original: `FUN_081e0ba4` @ 0x081e0ba4 (8 bytes,
/// 52 `bl` call sites, no `b` tail calls; verified by decoding every
/// branch word in osos.dec).
///
/// `ldrb r0, [r0, #12]; bx lr` — the whole function. Not a veneer: a
/// veneer is `ldr pc, [pc, #-4]` plus a target word.
///
/// Returns the kind byte [`event_source_construct`] stored at +0x0c. Call
/// sites treat it as a small enumeration: the transition state machine @
/// 0x0817f7c0 compares two sources' kinds against 1, 5, 6, 9 and 10 to
/// decide whether a view change animates.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_source_kind(source: *const u8) -> u8 {
    unsafe { source.add(EVENT_SOURCE_KIND_OFFSET).read() }
}

/// event_source_construct — original: `FUN_081e0bac` @ 0x081e0bac
/// (136 bytes: 33 instructions plus the literal pool word at 0x081e0c30
/// that Ghidra's 132-byte extent drops; the next function starts at
/// 0x081e0c34. 128 `bl` call sites, no `b` tail calls, both counts
/// verified by decoding every branch word in osos.dec).
///
/// Installs [`EVENT_SOURCE_VTABLE`], then default-constructs the three
/// sub-objects in ascending order — the declaration vector at +0x10, the
/// child collection at +0x1c, the event tree at +0x38 — chaining each
/// constructor's returned `this` into the next one's address. It then
/// clears the owning-registry word at +0x58 and stores the three
/// arguments. A positive id loads the declaration vector from the registry
/// and clears the event tree's built flag.
///
/// Two details are load-bearing and preserved verbatim:
///
/// * the id test is `cmp r6,#0; ble` — signed, so a negative id skips the
///   load exactly like a zero id does;
/// * the built flag at +0x54 is written *only* on that path. A source
///   with a non-positive id leaves the flag at whatever its storage held,
///   which for the stack temporaries built @ 0x0817ead0 and @ 0x08183638
///   is uninitialized. Those two sites both pass a caller-checked non-zero
///   id, so the original never observes it; the port does not add a store
///   the original does not make.
///
/// Deviation: the original passes uninitialized stack slots as the ignored
/// allocator arguments (sp+20 and sp+12). The port passes zeroed ones. The
/// comparator bytes at sp+16 and sp+8, which the collection constructors
/// do read, are zeroed by the original and by the port.
///
/// Returns `source`, as the original does through `mov r0, r4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_source_construct(
    source: *mut u8,
    id: i32,
    kind: u8,
    declaration: u32,
) -> *mut u8 {
    let ops = unsafe { construct_ops() };
    let mut comparator: u32 = 0;
    let mut allocator: u32 = 0;

    unsafe { source.cast::<u32>().write(EVENT_SOURCE_VTABLE) };

    let vector = unsafe {
        (ops.construct_declaration_vector)(
            source.add(EVENT_SOURCE_EVENT_BEGIN_OFFSET),
            (&mut allocator as *mut u32).cast(),
        )
    };
    let children = unsafe {
        (ops.construct_child_collection)(
            vector.add(EVENT_SOURCE_CHILDREN_OFFSET - EVENT_SOURCE_EVENT_BEGIN_OFFSET),
            (&mut comparator as *mut u32).cast(),
            (&mut allocator as *mut u32).cast(),
        )
    };
    let list = unsafe {
        (ops.construct_event_list)(
            children.add(EVENT_LIST_OFFSET - EVENT_SOURCE_CHILDREN_OFFSET),
            (&mut comparator as *mut u32).cast(),
            (&mut allocator as *mut u32).cast(),
        )
    };

    let source = unsafe { list.sub(EVENT_LIST_OFFSET) };
    unsafe {
        source
            .add(EVENT_SOURCE_OPTIONAL_EVENT_OFFSET)
            .cast::<u32>()
            .write(0);
        source
            .add(EVENT_SOURCE_PRIMARY_EVENT_OFFSET)
            .cast::<i32>()
            .write(id);
        source
            .add(EVENT_SOURCE_DECLARATION_OFFSET)
            .cast::<u32>()
            .write(declaration);
        source.add(EVENT_SOURCE_KIND_OFFSET).write(kind);
    }

    if id > 0 {
        unsafe { (ops.load_declarations)(source) };
        unsafe { source.add(EVENT_LIST_BUILT_OFFSET).write(0) };
    }
    source
}

/// Sub-object teardowns the destructor calls through. Like the
/// construction table above, each is a distinct unported firmware routine
/// and each pointer-returning one returns its own `this`.
#[derive(Clone, Copy)]
pub struct EventSourceDestructOps {
    /// Original 0x082a7fd8: destroys the event tree at +0x38. Its body is
    /// instruction-for-instruction the same tree teardown this function
    /// inlines for the child collection, but bound to the other node
    /// allocator family (0x083c1c3c / 0x083c1648).
    pub destroy_event_list: unsafe extern "C" fn(*mut u8) -> *mut u8,
    /// Original 0x083ba534: the child collection's range erase,
    /// `erase(result, tree, first, last)`. `result` is the four-byte
    /// iterator slot the ARM passes as `add r0, sp, #8`.
    pub erase_child_range:
        unsafe extern "C" fn(*mut u32, *mut u8, *mut u32, *mut u32),
    /// Original 0x083b9ffc: pushes a node onto the collection's
    /// recycled-node list. The third argument selects value destruction;
    /// the destructor passes 0 because the node it recycles is the
    /// collection's valueless header sentinel.
    pub recycle_child_node: unsafe extern "C" fn(*mut u8, *mut u8, u32),
    /// Original 0x083e4b2c: destroys the declaration vector at +0x10 —
    /// the counterpart of `construct_declaration_vector`.
    pub destroy_declaration_vector: unsafe extern "C" fn(*mut u8) -> *mut u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_destroy_event_list(tree: *mut u8) -> *mut u8 {
    let destroy: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(0x082a_7fd8usize) };
    unsafe { destroy(tree) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_erase_child_range(
    result: *mut u32,
    collection: *mut u8,
    first: *mut u32,
    last: *mut u32,
) {
    let erase: unsafe extern "C" fn(*mut u32, *mut u8, *mut u32, *mut u32) =
        unsafe { core::mem::transmute(0x083b_a534usize) };
    unsafe { erase(result, collection, first, last) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_recycle_child_node(
    collection: *mut u8,
    node: *mut u8,
    destroy_value: u32,
) {
    let recycle: unsafe extern "C" fn(*mut u8, *mut u8, u32) =
        unsafe { core::mem::transmute(0x083b_9ffcusize) };
    unsafe { recycle(collection, node, destroy_value) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_destroy_declaration_vector(vector: *mut u8) -> *mut u8 {
    let destroy: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(0x083e_4b2cusize) };
    unsafe { destroy(vector) }
}

/// Host defaults. Unlike the construction table's, these cannot be faked
/// by returning `this`: every one of them frees storage, and a silent
/// no-op would let a test claim a teardown happened that did not. Tests
/// install recording replacements; anything else is a bug worth a panic.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_event_list(_tree: *mut u8) -> *mut u8 {
    panic!("event_source_destruct requires event-tree teardown 0x082a7fd8")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_erase_child_range(
    _result: *mut u32,
    _collection: *mut u8,
    _first: *mut u32,
    _last: *mut u32,
) {
    panic!("event_source_destruct requires child range erase 0x083ba534")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_recycle_child_node(
    _collection: *mut u8,
    _node: *mut u8,
    _destroy_value: u32,
) {
    panic!("event_source_destruct requires node recycle 0x083b9ffc")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_declaration_vector(_vector: *mut u8) -> *mut u8 {
    panic!("event_source_destruct requires vector teardown 0x083e4b2c")
}

/// Active sub-object teardowns for [`event_source_destruct`].
#[cfg(target_os = "none")]
pub static mut EVENT_SOURCE_DESTRUCT_OPS: EventSourceDestructOps = EventSourceDestructOps {
    destroy_event_list: firmware_destroy_event_list,
    erase_child_range: firmware_erase_child_range,
    recycle_child_node: firmware_recycle_child_node,
    destroy_declaration_vector: firmware_destroy_declaration_vector,
};

#[cfg(not(target_os = "none"))]
pub static mut EVENT_SOURCE_DESTRUCT_OPS: EventSourceDestructOps = EventSourceDestructOps {
    destroy_event_list: missing_destroy_event_list,
    erase_child_range: missing_erase_child_range,
    recycle_child_node: missing_recycle_child_node,
    destroy_declaration_vector: missing_destroy_declaration_vector,
};

#[inline(always)]
unsafe fn destruct_ops() -> EventSourceDestructOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_SOURCE_DESTRUCT_OPS)) }
}

/// Reads one u32 word of the opaque target layout. These words are 32-bit
/// target pointers, so host fixtures backing them must sit below 4 GiB
/// (`crate::testing::try_map_u32_slab`).
#[inline(always)]
unsafe fn word(at: *const u8) -> u32 {
    unsafe { at.cast::<u32>().read() }
}

/// event_source_destruct — original: `FUN_081e0c4c` @ 0x081e0c4c
/// (160 bytes: 39 instructions plus the literal pool word at 0x081e0ce8
/// that Ghidra's 156-byte extent drops; the next function starts at
/// 0x081e0cec. 128 `bl` call sites and no `b` tail calls, both verified by
/// decoding every branch word in osos.dec — the very same 128 sites that
/// call [`event_source_construct`], which is what identifies this as that
/// constructor's non-deleting destructor. The deleting form is the
/// six-instruction thunk @ 0x081e0c34: `cmp r0,#0; bl 0x081e0c4c; b
/// operator_delete`.)
///
/// Reinstalls [`EVENT_SOURCE_VTABLE`] — the same literal the constructor
/// stores, from a second copy of the word — then unwinds the three
/// sub-objects in reverse construction order:
///
/// 1. the event tree at +0x38, through firmware 0x082a7fd8;
/// 2. the child collection at +0x1c, whose teardown is *inlined* here
///    rather than called: erase `[begin, end)`, recycle the header
///    sentinel node, then free every chunk record of the collection's
///    embedded node pool (see
///    [`crate::app::event_list::TREE_POOL_CHUNKS_OFFSET`]);
/// 3. the declaration vector at +0x10, through firmware 0x083e4b2c.
///
/// Each step addresses its sub-object relative to the *previous callee's
/// returned pointer*, never relative to `source` — `sub r4, r0, #28` and
/// `sub r0, r4, #12` — and the final `sub r0, r0, #16` recovers `source`
/// from the vector teardown's result. The port keeps that chain intact,
/// because it is what makes the function work for a `source` the caller
/// reached through a base-class pointer.
///
/// Two details are load-bearing and preserved verbatim:
///
/// * the whole collection teardown, chunk-pool walk included, sits under
///   the single `if header != 0` test on the collection's header word. A
///   collection whose header was never allocated leaks nothing, because
///   the pool that would hold chunks is the header's own allocator;
/// * the header word is re-read from the collection *after* the range
///   erase, so the node handed to the recycle call is whatever the erase
///   left behind, not the value captured before it.
///
/// Deviation: the original reads the header word twice in a row before
/// the erase (`ldr r0, [r0, #-12]` then `ldr r0, [r4, #16]`, no call in
/// between) to form the two iterator slots; the port reads it once.
///
/// # Safety
///
/// `source` must point at 0x5c writable, word-aligned bytes holding a
/// constructed event source; the collection's header and pool words must
/// name live target allocations. All as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_source_destruct(source: *mut u8) -> *mut u8 {
    let ops = unsafe { destruct_ops() };
    unsafe { source.cast::<u32>().write(EVENT_SOURCE_VTABLE) };

    let list = unsafe { (ops.destroy_event_list)(source.add(EVENT_LIST_OFFSET)) };
    let children = unsafe { list.sub(EVENT_LIST_OFFSET - EVENT_SOURCE_CHILDREN_OFFSET) };

    let mut header = unsafe { word(children.add(TREE_HEADER_OFFSET)) };
    if header != 0 {
        let mut leftmost =
            unsafe { word((header as usize as *const u8).add(TREE_LEFTMOST_OFFSET)) };
        // The four-byte iterator the erase returns; the original reserves
        // it as a stack slot (`add r0, sp, #8`, one of the words its
        // prologue pushed) and never looks at it again, so it is never
        // initialized either.
        let mut erased = core::mem::MaybeUninit::<u32>::uninit();
        unsafe {
            (ops.erase_child_range)(
                erased.as_mut_ptr(),
                children,
                &mut leftmost,
                &mut header,
            )
        };

        let sentinel = unsafe { word(children.add(TREE_HEADER_OFFSET)) };
        unsafe { (ops.recycle_child_node)(children, sentinel as usize as *mut u8, 0) };

        loop {
            let chunk = unsafe { word(children.add(TREE_POOL_CHUNKS_OFFSET)) };
            if chunk == 0 {
                break;
            }
            let chunk = chunk as usize as *mut u8;
            let next = unsafe { word(chunk.add(CHUNK_NEXT_OFFSET)) };
            unsafe {
                children
                    .add(TREE_POOL_CHUNKS_OFFSET)
                    .cast::<u32>()
                    .write(next);
                crate::heap::veneers::cxx_array_dealloc(
                    word(chunk.add(CHUNK_BLOCK_OFFSET)) as usize as *mut u8,
                    word(chunk.add(CHUNK_CAPACITY_OFFSET)) as usize,
                    0,
                );
                crate::heap::veneers::cxx_array_dealloc(chunk, 1, 0);
            }
        }
    }

    let vector = unsafe {
        (ops.destroy_declaration_vector)(
            children.sub(EVENT_SOURCE_CHILDREN_OFFSET - EVENT_SOURCE_EVENT_BEGIN_OFFSET),
        )
    };
    unsafe { vector.sub(EVENT_SOURCE_EVENT_BEGIN_OFFSET) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<Call> = Vec::new();

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        DeclarationVector { at: usize },
        ChildCollection { at: usize, comparator: u8 },
        EventList { at: usize, comparator: u8 },
        LoadDeclarations { source: usize },
    }

    unsafe extern "C" fn recording_vector(vector: *mut u8, _allocator: *mut u8) -> *mut u8 {
        unsafe { CALLS.push(Call::DeclarationVector { at: vector as usize }) };
        vector
    }

    unsafe extern "C" fn recording_children(
        collection: *mut u8,
        comparator: *mut u8,
        _allocator: *mut u8,
    ) -> *mut u8 {
        unsafe {
            CALLS.push(Call::ChildCollection {
                at: collection as usize,
                comparator: comparator.read(),
            })
        };
        collection
    }

    unsafe extern "C" fn recording_list(
        tree: *mut u8,
        comparator: *mut u8,
        _allocator: *mut u8,
    ) -> *mut u8 {
        unsafe {
            CALLS.push(Call::EventList {
                at: tree as usize,
                comparator: comparator.read(),
            })
        };
        tree
    }

    unsafe extern "C" fn recording_load(source: *mut u8) {
        unsafe { CALLS.push(Call::LoadDeclarations { source: source as usize }) };
    }

    /// A source whose every byte starts at 0xaa, so any untouched field is
    /// visibly untouched.
    #[repr(C, align(4))]
    struct Source([u8; EVENT_SOURCE_SIZE]);

    /// Constructs in place: the object must not move, because the
    /// recorded call addresses are relative to its base.
    fn construct(source: &mut Source, id: i32, kind: u8, declaration: u32) -> Vec<Call> {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        source.0 = [0xaa; EVENT_SOURCE_SIZE];
        unsafe {
            CALLS.clear();
            EVENT_SOURCE_CONSTRUCT_OPS = EventSourceConstructOps {
                construct_declaration_vector: recording_vector,
                construct_child_collection: recording_children,
                construct_event_list: recording_list,
                load_declarations: recording_load,
            };
            let returned = event_source_construct(source.0.as_mut_ptr(), id, kind, declaration);
            assert_eq!(returned, source.0.as_mut_ptr());
            EVENT_SOURCE_CONSTRUCT_OPS = EventSourceConstructOps {
                construct_declaration_vector: missing_construct_declaration_vector,
                construct_child_collection: missing_construct_child_collection,
                construct_event_list: missing_construct_event_list,
                load_declarations: missing_load_declarations,
            };
            CALLS.clone()
        }
    }

    fn word_at(source: &Source, offset: usize) -> u32 {
        u32::from_ne_bytes(source.0[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn kind_reads_only_the_byte_at_0x0c() {
        for kind in [0u8, 1, 5, 6, 9, 10, 0xff] {
            let mut source = [0u8; EVENT_SOURCE_SIZE];
            source[EVENT_SOURCE_KIND_OFFSET] = kind;
            source[EVENT_SOURCE_KIND_OFFSET + 1] = !kind;
            assert_eq!(unsafe { event_source_kind(source.as_ptr()) }, kind);
        }
    }

    #[test]
    fn constructs_sub_objects_in_ascending_order() {
        let mut source = Source([0; EVENT_SOURCE_SIZE]);
        let calls = construct(&mut source, 0x5345_5654u32 as i32, 6, 0x1234_5678);
        let base = source.0.as_ptr() as usize;
        assert_eq!(
            calls,
            std::vec![
                Call::DeclarationVector { at: base + 0x10 },
                Call::ChildCollection { at: base + 0x1c, comparator: 0 },
                Call::EventList { at: base + 0x38, comparator: 0 },
                Call::LoadDeclarations { source: base },
            ]
        );
    }

    #[test]
    fn stores_vtable_and_arguments() {
        let mut source = Source([0; EVENT_SOURCE_SIZE]);
        construct(&mut source, 0x5345_5654u32 as i32, 6, 0x1234_5678);
        assert_eq!(word_at(&source, 0x00), EVENT_SOURCE_VTABLE);
        assert_eq!(word_at(&source, EVENT_SOURCE_DECLARATION_OFFSET), 0x1234_5678);
        assert_eq!(
            word_at(&source, EVENT_SOURCE_PRIMARY_EVENT_OFFSET),
            0x5345_5654
        );
        assert_eq!(word_at(&source, EVENT_SOURCE_OPTIONAL_EVENT_OFFSET), 0);
        assert_eq!(source.0[EVENT_SOURCE_KIND_OFFSET], 6);
        // The kind is one byte wide: its neighbours survive.
        assert_eq!(source.0[EVENT_SOURCE_KIND_OFFSET + 1], 0xaa);
        assert_eq!(source.0[EVENT_SOURCE_KIND_OFFSET + 3], 0xaa);
        assert_eq!(source.0[EVENT_LIST_BUILT_OFFSET], 0);
    }

    #[test]
    fn a_positive_id_is_what_loads_declarations() {
        let mut source = Source([0; EVENT_SOURCE_SIZE]);
        for id in [1i32, 2, 0x5345_5654, i32::MAX] {
            let calls = construct(&mut source, id, 0, 0);
            assert_eq!(
                calls.last(),
                Some(&Call::LoadDeclarations {
                    source: source.0.as_ptr() as usize
                }),
                "id {id:#x} should load"
            );
            assert_eq!(source.0[EVENT_LIST_BUILT_OFFSET], 0);
        }
    }

    #[test]
    fn a_non_positive_id_neither_loads_nor_clears_the_built_flag() {
        // The test is signed, so -1 and i32::MIN skip exactly like 0 does;
        // an unsigned test would have loaded for both.
        let mut source = Source([0; EVENT_SOURCE_SIZE]);
        for id in [0i32, -1, -0x1000, i32::MIN] {
            let calls = construct(&mut source, id, 0, 0);
            assert_eq!(calls.len(), 3, "id {id:#x} should not load");
            assert_eq!(
                source.0[EVENT_LIST_BUILT_OFFSET],
                0xaa,
                "id {id:#x} must leave the built flag alone"
            );
        }
    }

    #[test]
    fn construction_writes_nothing_past_the_object() {
        // Everything above +0x58 belongs to the caller; +0x5c is the end.
        let mut source = Source([0; EVENT_SOURCE_SIZE]);
        construct(&mut source, 0, 0xff, u32::MAX);
        assert_eq!(word_at(&source, EVENT_SOURCE_DECLARATION_OFFSET), u32::MAX);
        assert_eq!(source.0[EVENT_SOURCE_KIND_OFFSET], 0xff);
        // The sub-object bodies are the stubs' business, not ours: with
        // recording stubs they stay untouched.
        assert!(source.0[EVENT_SOURCE_EVENT_BEGIN_OFFSET..EVENT_SOURCE_CHILDREN_OFFSET]
            .iter()
            .all(|&b| b == 0xaa));
        assert!(source.0[EVENT_SOURCE_CHILDREN_OFFSET..EVENT_LIST_OFFSET]
            .iter()
            .all(|&b| b == 0xaa));
        assert!(source.0[EVENT_LIST_OFFSET..EVENT_LIST_BUILT_OFFSET]
            .iter()
            .all(|&b| b == 0xaa));
    }
}

#[cfg(test)]
mod destruct_tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;

    static DESTRUCT_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<Call> = Vec::new();
    /// Non-null forces the matching teardown's return value, which is how
    /// the tests prove the port rebases off the callee's pointer.
    static mut EVENT_LIST_RESULT: *mut u8 = core::ptr::null_mut();
    static mut VECTOR_RESULT: *mut u8 = core::ptr::null_mut();

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        /// `source_vtable` is read back through the argument, so recording
        /// it proves the vtable store precedes the first teardown.
        DestroyEventList { at: usize, source_vtable: u32 },
        EraseChildRange { collection: usize, first: u32, last: u32 },
        RecycleChildNode { collection: usize, node: u32, destroy_value: u32 },
        DestroyDeclarationVector { at: usize },
    }

    unsafe extern "C" fn recording_destroy_event_list(tree: *mut u8) -> *mut u8 {
        unsafe {
            CALLS.push(Call::DestroyEventList {
                at: tree as usize,
                source_vtable: word(tree.sub(EVENT_LIST_OFFSET)),
            });
            let forced = core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_RESULT));
            if forced.is_null() {
                tree
            } else {
                forced
            }
        }
    }

    unsafe extern "C" fn recording_erase_child_range(
        result: *mut u32,
        collection: *mut u8,
        first: *mut u32,
        last: *mut u32,
    ) {
        unsafe {
            CALLS.push(Call::EraseChildRange {
                collection: collection as usize,
                first: first.read(),
                last: last.read(),
            });
            // The firmware erase writes the surviving iterator here.
            result.write(0xeeee_eeee);
        }
    }

    unsafe extern "C" fn recording_recycle_child_node(
        collection: *mut u8,
        node: *mut u8,
        destroy_value: u32,
    ) {
        unsafe {
            CALLS.push(Call::RecycleChildNode {
                collection: collection as usize,
                node: node as usize as u32,
                destroy_value,
            })
        };
    }

    unsafe extern "C" fn recording_destroy_declaration_vector(vector: *mut u8) -> *mut u8 {
        unsafe {
            CALLS.push(Call::DestroyDeclarationVector {
                at: vector as usize,
            });
            let forced = core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_RESULT));
            if forced.is_null() {
                vector
            } else {
                forced
            }
        }
    }

    const RECORDING_OPS: EventSourceDestructOps = EventSourceDestructOps {
        destroy_event_list: recording_destroy_event_list,
        erase_child_range: recording_erase_child_range,
        recycle_child_node: recording_recycle_child_node,
        destroy_declaration_vector: recording_destroy_declaration_vector,
    };

    /// Installs the recording table and the mock heap; both are global, so
    /// both guards are held for the whole test.
    fn mock() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let ops_guard = DESTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            core::ptr::addr_of_mut!(EVENT_SOURCE_DESTRUCT_OPS).write_volatile(RECORDING_OPS);
            CALLS.clear();
            EVENT_LIST_RESULT = core::ptr::null_mut();
            VECTOR_RESULT = core::ptr::null_mut();
        }
        (ops_guard, heap_guard)
    }

    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe {
            core::ptr::addr_of_mut!(EVENT_SOURCE_DESTRUCT_OPS).write_volatile(
                EventSourceDestructOps {
                    destroy_event_list: missing_destroy_event_list,
                    erase_child_range: missing_erase_child_range,
                    recycle_child_node: missing_recycle_child_node,
                    destroy_declaration_vector: missing_destroy_declaration_vector,
                },
            );
        }
        drop(guards);
    }

    fn calls() -> Vec<Call> {
        unsafe { CALLS.clone() }
    }

    /// A source whose child collection has no header. Nothing in this
    /// object is dereferenced through a u32 word, so it needs no low
    /// mapping and runs on every host.
    #[repr(align(4))]
    struct Source([u8; EVENT_SOURCE_SIZE]);

    #[test]
    fn a_headerless_collection_only_runs_the_two_sub_object_teardowns() {
        let guards = mock();
        let mut source = Source([0xa5; EVENT_SOURCE_SIZE]);
        // The header word is the single gate on the collection teardown.
        source.0[EVENT_SOURCE_CHILDREN_OFFSET + TREE_HEADER_OFFSET
            ..EVENT_SOURCE_CHILDREN_OFFSET + TREE_HEADER_OFFSET + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        let this = source.0.as_mut_ptr();
        unsafe {
            let returned = event_source_destruct(this);

            assert_eq!(returned, this, "the pointer chain lands back on source");
            assert_eq!(
                word(this),
                EVENT_SOURCE_VTABLE,
                "the destructor reinstalls the constructor's vtable"
            );
            assert_eq!(
                calls(),
                std::vec![
                    Call::DestroyEventList {
                        at: this.add(EVENT_LIST_OFFSET) as usize,
                        source_vtable: EVENT_SOURCE_VTABLE,
                    },
                    Call::DestroyDeclarationVector {
                        at: this.add(EVENT_SOURCE_EVENT_BEGIN_OFFSET) as usize,
                    },
                ],
                "no erase, no recycle, no pool walk without a header"
            );
            assert_eq!(free_log().0, 0, "and nothing reaches the heap");
        }
        restore(guards);
    }

    #[test]
    fn every_sub_object_address_comes_from_the_previous_callee_result() {
        let guards = mock();
        // A relocated event-tree teardown result puts the collection —
        // and therefore the declaration vector — somewhere else entirely.
        let mut elsewhere = Source([0; EVENT_SOURCE_SIZE]);
        let mut source = Source([0; EVENT_SOURCE_SIZE]);
        let this = source.0.as_mut_ptr();
        // `elsewhere + 0x1c` plays the collection; its header word is the
        // zero the array is already filled with.
        let relocated_list = unsafe {
            elsewhere
                .0
                .as_mut_ptr()
                .add(EVENT_LIST_OFFSET - EVENT_SOURCE_CHILDREN_OFFSET)
        };
        unsafe {
            EVENT_LIST_RESULT = relocated_list;
            let returned = event_source_destruct(this);

            let collection = relocated_list.sub(EVENT_LIST_OFFSET - EVENT_SOURCE_CHILDREN_OFFSET);
            let vector = collection
                .sub(EVENT_SOURCE_CHILDREN_OFFSET - EVENT_SOURCE_EVENT_BEGIN_OFFSET);
            assert_eq!(
                calls()[1],
                Call::DestroyDeclarationVector { at: vector as usize },
                "the vector address is the tree result minus 0x1c minus 0xc"
            );
            assert_eq!(
                returned,
                vector.sub(EVENT_SOURCE_EVENT_BEGIN_OFFSET),
                "and the result is the vector teardown's pointer minus 0x10"
            );
            assert_ne!(returned, this, "which is deliberately not `source`");
        }
        restore(guards);
    }

    // --- the populated collection path: u32 target pointers, low fixture ---

    const SLAB_HINT: usize = crate::testing::hints::EVENT_SOURCE_DESTRUCT;
    const SLAB_LEN: usize = 0x1000;
    /// Where the fixture puts the collection's header sentinel, its
    /// leftmost node, and the node pool's chunk records and blocks.
    const HEADER_AT: usize = 0x100;
    const LEFTMOST_AT: usize = 0x140;
    const CHUNK_AT: [usize; 2] = [0x200, 0x240];
    const BLOCK_AT: [usize; 2] = [0x300, 0x400];

    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(SLAB_HINT, SLAB_LEN).map(|p| p as usize));

    /// One low mapping serves every populated-collection test; the lock
    /// each test holds makes the reuse safe.
    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    unsafe fn put_word(at: *mut u8, value: u32) {
        unsafe { at.cast::<u32>().write(value) };
    }

    /// Builds a source at the slab base whose child collection owns a
    /// header sentinel plus `chunks` node-pool chunk records. Returns
    /// `source`.
    unsafe fn install_source(slab: *mut u8, chunks: usize) -> *mut u8 {
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let collection = slab.add(EVENT_SOURCE_CHILDREN_OFFSET);
            put_word(
                collection.add(TREE_HEADER_OFFSET),
                slab.add(HEADER_AT) as usize as u32,
            );
            put_word(
                slab.add(HEADER_AT + TREE_LEFTMOST_OFFSET),
                slab.add(LEFTMOST_AT) as usize as u32,
            );
            let mut head = 0u32;
            for index in (0..chunks).rev() {
                let chunk = slab.add(CHUNK_AT[index]);
                put_word(chunk.add(CHUNK_NEXT_OFFSET), head);
                put_word(chunk.add(CHUNK_CAPACITY_OFFSET), 32 + index as u32);
                put_word(
                    chunk.add(CHUNK_BLOCK_OFFSET),
                    slab.add(BLOCK_AT[index]) as usize as u32,
                );
                head = chunk as usize as u32;
            }
            put_word(collection.add(TREE_POOL_CHUNKS_OFFSET), head);
            slab
        }
    }

    #[test]
    fn a_populated_collection_is_erased_then_its_header_node_recycled() {
        let Some(slab) = try_slab() else {
            assert!(note_missing_u32_fixture("app::event_source::destruct"));
            return;
        };
        let guards = mock();
        unsafe {
            let this = install_source(slab, 0);
            let collection = this.add(EVENT_SOURCE_CHILDREN_OFFSET);
            let header = word(collection.add(TREE_HEADER_OFFSET));

            event_source_destruct(this);

            assert_eq!(
                calls()[1],
                Call::EraseChildRange {
                    collection: collection as usize,
                    first: word(slab.add(HEADER_AT + TREE_LEFTMOST_OFFSET)),
                    last: header,
                },
                "erase([begin, end)) — begin is header->left, end is header"
            );
            assert_eq!(
                calls()[2],
                Call::RecycleChildNode {
                    collection: collection as usize,
                    node: header,
                    destroy_value: 0,
                },
                "the valueless sentinel is recycled without value destruction"
            );
            assert_eq!(calls().len(), 4, "and the two sub-object teardowns bracket it");
            assert_eq!(free_log().0, 0, "an empty node pool frees nothing");
        }
        restore(guards);
    }

    #[test]
    fn the_recycled_node_is_re_read_after_the_erase() {
        let Some(slab) = try_slab() else {
            assert!(note_missing_u32_fixture("app::event_source::destruct"));
            return;
        };
        let guards = mock();
        unsafe {
            let this = install_source(slab, 0);
            let collection = this.add(EVENT_SOURCE_CHILDREN_OFFSET);
            // An erase that swaps the header out must be followed.
            let replacement = slab.add(LEFTMOST_AT) as usize as u32;
            unsafe extern "C" fn erase_then_swap_header(
                result: *mut u32,
                collection: *mut u8,
                first: *mut u32,
                last: *mut u32,
            ) {
                unsafe {
                    recording_erase_child_range(result, collection, first, last);
                    let swapped = core::ptr::read_volatile(core::ptr::addr_of!(SWAPPED_HEADER));
                    put_word(collection.add(TREE_HEADER_OFFSET), swapped);
                }
            }
            SWAPPED_HEADER = replacement;
            core::ptr::addr_of_mut!(EVENT_SOURCE_DESTRUCT_OPS.erase_child_range)
                .write_volatile(erase_then_swap_header);

            event_source_destruct(this);

            assert_eq!(
                calls()[2],
                Call::RecycleChildNode {
                    collection: collection as usize,
                    node: replacement,
                    destroy_value: 0,
                },
                "the header word is re-read after the erase, not cached"
            );
        }
        restore(guards);
    }

    static mut SWAPPED_HEADER: u32 = 0;

    #[test]
    fn the_node_pool_is_drained_block_before_record_in_list_order() {
        let Some(slab) = try_slab() else {
            assert!(note_missing_u32_fixture("app::event_source::destruct"));
            return;
        };
        let guards = mock();
        unsafe {
            let this = install_source(slab, 2);
            let collection = this.add(EVENT_SOURCE_CHILDREN_OFFSET);

            event_source_destruct(this);

            let (frees, last, tag) = free_log();
            assert_eq!(frees, 4, "two records, each with its block");
            assert_eq!(
                last,
                slab.add(CHUNK_AT[1]),
                "the last free is the second record — records follow their blocks"
            );
            assert_eq!(tag, 2, "through the tag-2 operator delete");
            assert_eq!(
                word(collection.add(TREE_POOL_CHUNKS_OFFSET)),
                0,
                "the list head is unlinked one record at a time and ends empty"
            );
        }
        restore(guards);
    }

    #[test]
    fn a_record_without_a_block_still_frees_the_record() {
        let Some(slab) = try_slab() else {
            assert!(note_missing_u32_fixture("app::event_source::destruct"));
            return;
        };
        let guards = mock();
        unsafe {
            let this = install_source(slab, 1);
            // NULL blocks are the guarded `operator delete`'s business;
            // the record itself must still go.
            put_word(slab.add(CHUNK_AT[0] + CHUNK_BLOCK_OFFSET), 0);

            event_source_destruct(this);

            let (frees, last, _) = free_log();
            assert_eq!(frees, 1, "the NULL block is swallowed by operator delete");
            assert_eq!(last, slab.add(CHUNK_AT[0]), "the record still goes");
        }
        restore(guards);
    }
}
