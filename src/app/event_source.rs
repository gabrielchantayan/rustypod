//! The 92-byte retailOS event source object: construction and its kind byte.
//!
//! [`crate::app::event_list`] ports the lazily-built event tree that lives
//! at +0x38 of this object. This module ports the object's own constructor
//! and the accessor for its kind byte, so the two together cover the
//! source's construction seam.
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
    EVENT_LIST_BUILT_OFFSET, EVENT_LIST_OFFSET, EVENT_SOURCE_EVENT_BEGIN_OFFSET,
    EVENT_SOURCE_OPTIONAL_EVENT_OFFSET, EVENT_SOURCE_PRIMARY_EVENT_OFFSET,
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
