//! `element_registry_add` — original: `FUN_0816e020` @ 0x0816e020
//! (56 bytes).
//!
//! # Algorithm
//!
//! The registration wrapper of the 0x3c-byte UI element registry — the
//! object handed out by `lazy_singleton_0x3c` @ 0x0816df60 (ported in
//! `app/singletons.rs`), whose callers build a view, then call
//! `FUN_0816e020(registry, element)` followed by the by-id naming
//! routine @ 0x0816e220 (element id at element +0x04, name stored at
//! element +0x08). The body is two virtual dispatches and nothing else:
//!
//! ```text
//! 0816e020  push {r3, r4, r5, lr}
//! 0816e024  mov  r5, r0              @ r5 = registry
//! 0816e028  ldr  r0, [r1]            @ element->vtable
//! 0816e02c  mov  r4, r1              @ r4 = element
//! 0816e030  ldr  r1, [r0, #8]        @ slot +0x08
//! 0816e034  mov  r0, r4
//! 0816e038  blx  r1                  @ element->vtable[2](element)
//! 0816e03c  str  r4, [sp]            @ slot = element
//! 0816e040  ldr  r0, [r5]            @ registry->vtable (loaded AFTER the first call)
//! 0816e044  mov  r1, sp              @ &slot
//! 0816e048  ldr  r2, [r0, #28]       @ slot +0x1c
//! 0816e04c  mov  r0, r5
//! 0816e050  blx  r2                  @ registry->vtable[7](registry, &slot)
//! 0816e054  pop  {r3, r4, r5, pc}
//! ```
//!
//! First the element's own slot +0x08 runs on the element — a
//! pre-insert lifecycle hook, retain/activate in shape (the sibling
//! removal routine @ 0x0816e058 pairs a slot +0x0c predicate with a
//! slot +0x10 teardown on the same object), then the registry's slot
//! +0x1c receives `(registry, &slot)` where `slot` is a stack word
//! holding the element pointer, passed by reference so the callee may
//! replace it. Both return values are dead: every one of the 25 call
//! sites discards r0, so the recovered ABI is `void`. There are no
//! NULL guards anywhere; a null registry or element dereferences
//! exactly as the retail body does.
//!
//! # Verified facts
//!
//! Extent confirmed at exactly 56 bytes: the next function opens at
//! 0x0816e058 (`push {r4, r5, r6, r7, lr}; sub sp, #28`, Ghidra's
//! `FUN_0816e058`). Call count verified by decoding every B/BL word in
//! `work/firmware/osos.dec`: **25 `bl` call sites, 0 predicated forms,
//! 0 plain `b`, and 0 occurrences of 0x0816e020 as a data word** — the
//! wrapper itself is never dispatched virtually.
//!
//! Ghidra's C (`decomp/c/015/0816e020_FUN_0816e020.c`) is wrong about
//! the prototype: it invents four parameters, but r2/r3 are dead on
//! entry (the first `blx` overwrites r1 and the second overwrites
//! r1/r2 before any read), and its `local_10 = param_4` is a phantom —
//! the stack slot is written exactly once, with the element pointer.
//!
//! # Unresolved callees (documented, not invented)
//!
//! Both dispatch targets are runtime vtable data that does not decode
//! from the static image. The registry ctor @ 0x0816e2ac installs
//! vtable 0x089a4c20, whose slot +0x1c word reads 0x08102f44 — a
//! mid-function address (the containing body's prologue is at
//! 0x08102f30: `push {r4-r7, lr}; sub sp, #28`), an entry into which
//! would unbalance the stack; sibling slots +0x08/+0x0c/+0x14/+0x18
//! are zero. The element class (built by `FUN_0817e3b0`, vtable
//! 0x08989468) has slot +0x08 reading 0x6c695354 = ASCII "TSil" — the
//! known page mismatch where the 0x0898xxxx-0x089axxxx region holds
//! the C++ name blob in the static image while the real vtables are
//! initialized at runtime (same anomaly as clock_source_construct @
//! 0x08262958 and class_6800's FRAMEWORK_BASE_VTABLE). The port
//! therefore dispatches through whatever vtable the objects carry at
//! runtime and encodes nothing about the targets.
//!
//! Deviation: none beyond the structural vtable model — host pointers
//! are wider than the target's 32-bit vtable words, so the modeled
//! vtables use `usize` fillers to keep named slots at their target
//! byte offsets on device and disjoint on a 64-bit host.

/// A vtable-bearing UI element, as seen by the registry. Only the
/// vtable word is modeled; the element id at +0x04 and the name word
/// at +0x08 belong to the naming/removal siblings @ 0x0816e220 /
/// 0x0816e058 and are not touched here.
#[repr(C)]
pub struct RegistryElement {
    /// +0x00: the element's vtable.
    pub vtable: *const ElementVtable,
}

/// The element vtable, modeled down to the slot this wrapper
/// dispatches.
#[repr(C)]
pub struct ElementVtable {
    /// Slots +0x00/+0x04: not dispatched here.
    pub unresolved_00_04: [usize; 2],
    /// +0x08: the pre-insert lifecycle hook, invoked on the element
    /// immediately before registration. Retain/activate in shape (the
    /// removal routine pairs slot +0x0c with a slot +0x10 teardown on
    /// the same object), but the static image cannot name it — see the
    /// module header.
    pub pre_insert: unsafe extern "C" fn(this: *mut RegistryElement),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(ElementVtable, pre_insert)];

/// The 0x3c-byte registry object handed out by `lazy_singleton_0x3c`.
/// Only the vtable word is modeled; the collection head (+0x30) and
/// the two current-element slots (+0x18/+0x1c) belong to the unported
/// siblings.
#[repr(C)]
pub struct ElementRegistry {
    /// +0x00: the registry's vtable.
    pub vtable: *const RegistryVtable,
}

/// The registry vtable, modeled down to the slot this wrapper
/// dispatches.
#[repr(C)]
pub struct RegistryVtable {
    /// Slots +0x00..+0x18: not dispatched here.
    pub unresolved_00_18: [usize; 7],
    /// +0x1c: inserts the element referenced by `slot` into the
    /// registry's collection. `slot` is passed by reference; the callee
    /// may overwrite it. Its return value is dead at every call site.
    pub insert: unsafe extern "C" fn(
        this: *mut ElementRegistry,
        slot: *mut *mut RegistryElement,
    ),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(RegistryVtable, insert)];

/// element_registry_add — original: `FUN_0816e020` @ 0x0816e020
/// (56 bytes; 25 `bl` call sites, binary-verified).
///
/// Runs `element`'s vtable slot +0x08 on the element, then dispatches
/// `registry`'s vtable slot +0x1c with `(registry, &slot)` where `slot`
/// is a local word holding `element`. The registry vtable is loaded
/// only after the first call returns, exactly as the original's `ldr
/// r0, [r5]` follows the first `blx`.
///
/// # Safety
///
/// `registry` and `element` must be non-NULL pointers to objects whose
/// first word is a readable vtable with valid +0x1c / +0x08 entries.
/// The original has no NULL guards; malformed pointers fault exactly as
/// on device.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_registry_add(
    registry: *mut ElementRegistry,
    element: *mut RegistryElement,
) {
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*element).vtable));
    ((*vtable).pre_insert)(element);

    let mut slot = element;
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*registry).vtable));
    ((*vtable).insert)(registry, core::ptr::addr_of_mut!(slot));
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    // Test 1 fixtures: record the event order and every argument.
    static ORDER: AtomicUsize = AtomicUsize::new(0);
    static PRE_ELEMENT: AtomicUsize = AtomicUsize::new(0);
    static INSERT_REGISTRY: AtomicUsize = AtomicUsize::new(0);
    static INSERT_ELEMENT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn rec_pre_insert(this: *mut RegistryElement) {
        PRE_ELEMENT.store(this as usize, Ordering::SeqCst);
        ORDER.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn rec_insert(
        this: *mut ElementRegistry,
        slot: *mut *mut RegistryElement,
    ) {
        INSERT_REGISTRY.store(this as usize, Ordering::SeqCst);
        INSERT_ELEMENT.store(slot.read() as usize, Ordering::SeqCst);
        // pre_insert must already have run.
        assert_eq!(ORDER.load(Ordering::SeqCst), 1);
        ORDER.fetch_add(1, Ordering::SeqCst);
    }

    static ELEMENT_VT: ElementVtable =
        ElementVtable { unresolved_00_04: [0; 2], pre_insert: rec_pre_insert };
    static REGISTRY_VT: RegistryVtable =
        RegistryVtable { unresolved_00_18: [0; 7], insert: rec_insert };

    #[test]
    fn pre_insert_runs_before_insert_with_forwarded_args() {
        ORDER.store(0, Ordering::SeqCst);
        let mut element = RegistryElement { vtable: &ELEMENT_VT };
        let mut registry = ElementRegistry { vtable: &REGISTRY_VT };
        let element_ptr = core::ptr::addr_of_mut!(element);
        let registry_ptr = core::ptr::addr_of_mut!(registry);

        unsafe { element_registry_add(registry_ptr, element_ptr) };

        assert_eq!(ORDER.load(Ordering::SeqCst), 2, "both slots dispatched exactly once");
        assert_eq!(PRE_ELEMENT.load(Ordering::SeqCst), element_ptr as usize);
        assert_eq!(INSERT_REGISTRY.load(Ordering::SeqCst), registry_ptr as usize);
        assert_eq!(
            INSERT_ELEMENT.load(Ordering::SeqCst),
            element_ptr as usize,
            "insert must receive a slot word holding the element pointer"
        );
    }

    // Test 2 fixtures: the slot is a real out-param the callee may
    // replace; the wrapper must neither re-read it nor fault.
    static SLOT_AFTER: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn nop_pre_insert(_this: *mut RegistryElement) {}

    unsafe extern "C" fn replacing_insert(
        _this: *mut ElementRegistry,
        slot: *mut *mut RegistryElement,
    ) {
        slot.write(core::ptr::null_mut());
        SLOT_AFTER.store(slot.read() as usize, Ordering::SeqCst);
    }

    static REPLACING_VT: RegistryVtable =
        RegistryVtable { unresolved_00_18: [0; 7], insert: replacing_insert };
    static NOP_ELEMENT_VT: ElementVtable =
        ElementVtable { unresolved_00_04: [0; 2], pre_insert: nop_pre_insert };

    #[test]
    fn insert_may_replace_the_slot() {
        let mut element = RegistryElement { vtable: &NOP_ELEMENT_VT };
        let mut registry = ElementRegistry { vtable: &REPLACING_VT };

        unsafe {
            element_registry_add(core::ptr::addr_of_mut!(registry), core::ptr::addr_of_mut!(element))
        };

        assert_eq!(SLOT_AFTER.load(Ordering::SeqCst), 0, "the callee's slot write lands");
    }

    // Test 3 fixtures: pin the load order — the registry vtable pointer
    // is read only AFTER pre_insert returns, so a hook that swaps it
    // redirects the insert dispatch.
    static SWAPPED_INSERT_RAN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn swapping_pre_insert(this: *mut RegistryElement) {
        // The hook receives only the element; reach the registry through
        // a side channel the same way any callee could mutate shared
        // state between the two dispatches.
        PRE_ELEMENT.store(this as usize, Ordering::SeqCst);
        let registry = SWAP_TARGET.load(Ordering::SeqCst) as *mut ElementRegistry;
        (*registry).vtable = &SECOND_REGISTRY_VT;
    }

    unsafe extern "C" fn first_insert(
        _this: *mut ElementRegistry,
        _slot: *mut *mut RegistryElement,
    ) {
    }

    unsafe extern "C" fn second_insert(
        _this: *mut ElementRegistry,
        _slot: *mut *mut RegistryElement,
    ) {
        SWAPPED_INSERT_RAN.fetch_add(1, Ordering::SeqCst);
    }

    static SWAP_TARGET: AtomicUsize = AtomicUsize::new(0);
    static FIRST_REGISTRY_VT: RegistryVtable =
        RegistryVtable { unresolved_00_18: [0; 7], insert: first_insert };
    static SECOND_REGISTRY_VT: RegistryVtable =
        RegistryVtable { unresolved_00_18: [0; 7], insert: second_insert };
    static SWAP_ELEMENT_VT: ElementVtable =
        ElementVtable { unresolved_00_04: [0; 2], pre_insert: swapping_pre_insert };

    #[test]
    fn registry_vtable_is_loaded_after_pre_insert() {
        SWAPPED_INSERT_RAN.store(0, Ordering::SeqCst);
        let mut element = RegistryElement { vtable: &SWAP_ELEMENT_VT };
        let mut registry = ElementRegistry { vtable: &FIRST_REGISTRY_VT };
        SWAP_TARGET.store(core::ptr::addr_of_mut!(registry) as usize, Ordering::SeqCst);

        unsafe {
            element_registry_add(core::ptr::addr_of_mut!(registry), core::ptr::addr_of_mut!(element))
        };

        assert_eq!(
            SWAPPED_INSERT_RAN.load(Ordering::SeqCst),
            1,
            "a vtable swap inside pre_insert redirects the insert dispatch"
        );
    }
}
