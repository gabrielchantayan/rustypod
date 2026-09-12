//! Resource-reference value lookup.
//!
//! `resource_reference_value` — original: `FUN_082a449c` @ `0x082a449c`
//! (120 bytes).
//!
//! Raw ARM body, decoded from `osos.dec`:
//!
//! ```text
//! 082a449c  push {r4,r5,r6,lr}
//! 082a44a0  mov  r4,r0
//! 082a44a4  ldr  r0,[r0]          @ reference vtable
//! 082a44a8  ldr  r1,[r0,#8]       @ vtable slot +0x08: is_valid(reference)
//! 082a44ac  mov  r0,r4
//! 082a44b0  blx  r1
//! 082a44b4  cmp  r0,#0
//! 082a44b8  popeq {r4,r5,r6,pc}
//! 082a44bc  ldr  r1,[r4,#8]       @ direct entry
//! 082a44c0  mov  r5,#0
//! 082a44c4  cmp  r1,#0
//! 082a44c8  ldrne r0,[r4,#12]     @ context
//! 082a44cc  ldrne r0,[r0,#0xf9c]  @ context resource index
//! 082a44d0  bne  0x082a4500
//! 082a44d4  ldr  r1,[r4,#4]       @ indirect source
//! 082a44d8  cmp  r1,#0
//! 082a44dc  beq  0x082a450c
//! 082a44e0  mov  r0,r4
//! 082a44e4  bl   0x082a2cac       @ resolve indirect entry
//! 082a44e8  cmp  r0,#0
//! 082a44ec  beq  0x082a450c
//! 082a44f0  ldr  r1,[r4,#12]
//! 082a44f4  ldr  r2,[r1,#0xf9c]
//! 082a44f8  mov  r1,r0
//! 082a44fc  mov  r0,r2
//! 082a4500  bl   0x080506bc       @ index lookup
//! 082a4504  cmp  r0,#0
//! 082a4508  ldrne r5,[r0,#12]     @ record value
//! 082a450c  mov  r0,r5
//! 082a4510  pop  {r4,r5,r6,pc}
//! ```
//!
//! The next separately linked function starts at `0x082a4514`, establishing
//! the exact 120-byte extent with no literal pool. A complete decode of every
//! ARM immediate B/BL word in `osos.dec` finds eight inbound calls, all
//! unconditional plain `bl` (no predicated forms or direct tail branches):
//! `0x0812f918`, `0x081f79a4`, `0x081fd178`, `0x08208b5c`, `0x0821dc8c`,
//! `0x0821efc8`, `0x0823a570`, and `0x0823a57c`.
//!
//! Algorithm: first ask the reference's vtable slot `+0x08` whether it is
//! valid. A valid reference supplies a direct entry at `+0x08`, or, when that
//! is null, resolves its non-null indirect source at `+0x04` through
//! `FUN_082a2cac`. It then looks the entry up in the resource index at
//! `reference->context(+0x0c)->+0xf9c` using `FUN_080506bc`, returning the
//! matched record's `+0x0c` word or zero on every failed lookup.
//!
//! Deliberate deviation: the two direct callees remain retailOS-owned.
//! Target builds call their verified fixed addresses. Host tests substitute
//! native callbacks through a private ops table; host pointer fields widen,
//! while target-only assertions preserve each ARM offset. The virtual method
//! has no recovered concrete identity, so this port preserves only its
//! binary-verified ABI and slot rather than inventing one.

/// Opaque entry accepted by the retailOS resource index.
#[repr(C)]
pub struct ResourceEntry {
    _private: [u8; 0],
}

/// Opaque resource index held by a root context.
#[repr(C)]
pub struct ResourceIndex {
    _private: [u8; 0],
}

/// Record returned by the resource index. Only `value` is read here.
#[repr(C)]
pub struct ResourceIndexRecord {
    _unknown_words: [u32; 3],
    pub value: u32,
}

/// Root context fragment used by this routine.
///
/// `resource_index` is at `+0xf9c` on ARM. The host naturally pads before the
/// pointer for its wider alignment; named fields avoid overlapping it with the
/// preceding words.
#[repr(C)]
pub struct ResourceReferenceContext {
    _before_resource_index: [u32; 0x3e7],
    pub resource_index: *mut ResourceIndex,
}

/// ABI of the reference-validity virtual method at vtable slot `+0x08`.
pub type ResourceReferenceIsValid = unsafe extern "C" fn(*mut ResourceReference) -> u32;

/// Only the vtable words touched by this routine.
#[repr(C)]
pub struct ResourceReferenceVtable {
    _slot_00: usize,
    _slot_04: usize,
    pub is_valid: ResourceReferenceIsValid,
}

/// Four-word resource-reference object consumed by the retailOS routine.
#[repr(C)]
pub struct ResourceReference {
    /// +0x00: virtual-method table.
    pub vtable: *const ResourceReferenceVtable,
    /// +0x04: source used only when `entry` is null.
    pub source: *mut u8,
    /// +0x08: directly resolved entry, if available.
    pub entry: *mut ResourceEntry,
    /// +0x0c: owning context containing the resource index.
    pub context: *mut ResourceReferenceContext,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::size_of::<ResourceReference>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(ResourceReference, entry)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ResourceReference, context)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::size_of::<ResourceReferenceVtable>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(ResourceReferenceVtable, is_valid)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0f9c] = [0; core::mem::offset_of!(ResourceReferenceContext, resource_index)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ResourceIndexRecord, value)];

type ResolveIndirectEntry = unsafe extern "C" fn(*mut ResourceReference, *mut u8) -> *mut ResourceEntry;
type LookupResourceEntry = unsafe extern "C" fn(*mut ResourceIndex, *mut ResourceEntry) -> *mut ResourceIndexRecord;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_indirect_entry(
    reference: *mut ResourceReference,
    source: *mut u8,
) -> *mut ResourceEntry {
    let resolver: ResolveIndirectEntry = core::mem::transmute(0x082a_2cacusize);
    resolver(reference, source)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_resource_entry(
    index: *mut ResourceIndex,
    entry: *mut ResourceEntry,
) -> *mut ResourceIndexRecord {
    let lookup: LookupResourceEntry = core::mem::transmute(0x0805_06bcusize);
    lookup(index, entry)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ResourceReferenceHostOps {
    resolve_indirect: ResolveIndirectEntry,
    lookup: LookupResourceEntry,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_indirect_entry(
    _reference: *mut ResourceReference,
    _source: *mut u8,
) -> *mut ResourceEntry {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_resource_lookup(
    _index: *mut ResourceIndex,
    _entry: *mut ResourceEntry,
) -> *mut ResourceIndexRecord {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
const DEFAULT_RESOURCE_REFERENCE_HOST_OPS: ResourceReferenceHostOps = ResourceReferenceHostOps {
    resolve_indirect: unavailable_indirect_entry,
    lookup: unavailable_resource_lookup,
};

#[cfg(not(target_os = "none"))]
static mut RESOURCE_REFERENCE_HOST_OPS: ResourceReferenceHostOps = DEFAULT_RESOURCE_REFERENCE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resolve_indirect_entry(
    reference: *mut ResourceReference,
    source: *mut u8,
) -> *mut ResourceEntry {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_REFERENCE_HOST_OPS));
    (ops.resolve_indirect)(reference, source)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_resource_entry(
    index: *mut ResourceIndex,
    entry: *mut ResourceEntry,
) -> *mut ResourceIndexRecord {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_REFERENCE_HOST_OPS));
    (ops.lookup)(index, entry)
}

/// Returns the resource-index value selected by `reference`, or zero.
///
/// # Safety
///
/// `reference`, its vtable and its context must be readable. The vtable slot
/// `+0x08` is called before any nullable reference field is examined. When
/// validity succeeds, the indirect resolver and resource-index lookup retain
/// the retailOS contracts at `0x082a2cac` and `0x080506bc` respectively.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_reference_value")]
pub unsafe extern "C" fn resource_reference_value(reference: *mut ResourceReference) -> u32 {
    let vtable = core::ptr::addr_of!((*reference).vtable).read_volatile();
    let is_valid = core::ptr::addr_of!((*vtable).is_valid).read_volatile();
    if is_valid(reference) == 0 {
        return 0;
    }

    let mut entry = core::ptr::addr_of!((*reference).entry).read_volatile();
    if entry.is_null() {
        let source = core::ptr::addr_of!((*reference).source).read_volatile();
        if source.is_null() {
            return 0;
        }
        entry = resolve_indirect_entry(reference, source);
        if entry.is_null() {
            return 0;
        }
    }

    let context = core::ptr::addr_of!((*reference).context).read_volatile();
    let index = core::ptr::addr_of!((*context).resource_index).read_volatile();
    let record = lookup_resource_entry(index, entry);
    if record.is_null() {
        0
    } else {
        core::ptr::addr_of!((*record).value).read_volatile()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut VALID_RESULT: u32 = 1;
    static mut VALID_CALLS: u32 = 0;
    static mut RESOLVED_ENTRY: *mut ResourceEntry = core::ptr::null_mut();
    static mut RESOLVE_CALL: Option<(*mut ResourceReference, *mut u8)> = None;
    static mut LOOKUP_RECORD: *mut ResourceIndexRecord = core::ptr::null_mut();
    static mut LOOKUP_CALL: Option<(*mut ResourceIndex, *mut ResourceEntry)> = None;

    unsafe extern "C" fn recording_is_valid(_reference: *mut ResourceReference) -> u32 {
        VALID_CALLS += 1;
        VALID_RESULT
    }

    unsafe extern "C" fn recording_resolve(
        reference: *mut ResourceReference,
        source: *mut u8,
    ) -> *mut ResourceEntry {
        RESOLVE_CALL = Some((reference, source));
        RESOLVED_ENTRY
    }

    unsafe extern "C" fn recording_lookup(
        index: *mut ResourceIndex,
        entry: *mut ResourceEntry,
    ) -> *mut ResourceIndexRecord {
        LOOKUP_CALL = Some((index, entry));
        LOOKUP_RECORD
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    struct Bench {
        _lock: TestLock,
    }

    fn bench(
        valid_result: u32,
        resolved_entry: *mut ResourceEntry,
        lookup_record: *mut ResourceIndexRecord,
    ) -> Bench {
        let lock = lock_ops();
        unsafe {
            VALID_RESULT = valid_result;
            VALID_CALLS = 0;
            RESOLVED_ENTRY = resolved_entry;
            RESOLVE_CALL = None;
            LOOKUP_RECORD = lookup_record;
            LOOKUP_CALL = None;
            core::ptr::addr_of_mut!(RESOURCE_REFERENCE_HOST_OPS).write_volatile(
                ResourceReferenceHostOps {
                    resolve_indirect: recording_resolve,
                    lookup: recording_lookup,
                },
            );
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RESOURCE_REFERENCE_HOST_OPS)
                    .write_volatile(DEFAULT_RESOURCE_REFERENCE_HOST_OPS);
            }
        }
    }

    fn vtable() -> ResourceReferenceVtable {
        ResourceReferenceVtable {
            _slot_00: 0,
            _slot_04: 0,
            is_valid: recording_is_valid,
        }
    }

    fn context(index: *mut ResourceIndex) -> ResourceReferenceContext {
        ResourceReferenceContext {
            _before_resource_index: [0; 0x3e7],
            resource_index: index,
        }
    }

    fn reference(
        vtable: *const ResourceReferenceVtable,
        source: *mut u8,
        entry: *mut ResourceEntry,
        context: *mut ResourceReferenceContext,
    ) -> ResourceReference {
        ResourceReference { vtable, source, entry, context }
    }

    #[test]
    fn invalid_reference_stops_before_resolution_or_lookup() {
        let _bench = bench(0, core::ptr::null_mut(), core::ptr::null_mut());
        let table = vtable();
        let mut reference = reference(
            &table,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        assert_eq!(unsafe { resource_reference_value(&mut reference) }, 0);
        assert_eq!(unsafe { VALID_CALLS }, 1);
        assert_eq!(unsafe { RESOLVE_CALL }, None);
        assert_eq!(unsafe { LOOKUP_CALL }, None);
    }

    #[test]
    fn direct_entry_is_looked_up_without_indirect_resolution() {
        let mut index_marker = 0u8;
        let mut direct_entry_marker = 0u8;
        let mut record = ResourceIndexRecord { _unknown_words: [0; 3], value: 0x51a7_c0de };
        let _bench = bench(
            1,
            core::ptr::null_mut(),
            &mut record,
        );
        let table = vtable();
        let mut context = context((&mut index_marker as *mut u8).cast());
        let mut reference = reference(
            &table,
            core::ptr::null_mut(),
            (&mut direct_entry_marker as *mut u8).cast(),
            &mut context,
        );

        assert_eq!(unsafe { resource_reference_value(&mut reference) }, 0x51a7_c0de);
        assert_eq!(unsafe { RESOLVE_CALL }, None, "direct entry must skip 0x082a2cac");
        assert_eq!(
            unsafe { LOOKUP_CALL },
            Some(((&mut index_marker as *mut u8).cast(), (&mut direct_entry_marker as *mut u8).cast()))
        );
    }

    #[test]
    fn indirect_source_is_resolved_then_looked_up() {
        let mut index_marker = 0u8;
        let mut source_marker = 0u8;
        let mut resolved_entry_marker = 0u8;
        let mut record = ResourceIndexRecord { _unknown_words: [0; 3], value: 0x1234_5678 };
        let _bench = bench(
            1,
            (&mut resolved_entry_marker as *mut u8).cast(),
            &mut record,
        );
        let table = vtable();
        let mut context = context((&mut index_marker as *mut u8).cast());
        let mut reference = reference(
            &table,
            &mut source_marker,
            core::ptr::null_mut(),
            &mut context,
        );

        assert_eq!(unsafe { resource_reference_value(&mut reference) }, 0x1234_5678);
        let resolve_call = unsafe { RESOLVE_CALL }.expect("missing indirect resolution");
        assert_eq!(resolve_call.0, &mut reference as *mut _);
        assert_eq!(resolve_call.1, &mut source_marker as *mut u8);
        assert_eq!(
            unsafe { LOOKUP_CALL },
            Some(((&mut index_marker as *mut u8).cast(), (&mut resolved_entry_marker as *mut u8).cast()))
        );
    }

    #[test]
    fn null_source_cannot_resolve_a_missing_direct_entry() {
        let _bench = bench(1, core::ptr::null_mut(), core::ptr::null_mut());
        let table = vtable();
        let mut reference = reference(
            &table,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        assert_eq!(unsafe { resource_reference_value(&mut reference) }, 0);
        assert_eq!(unsafe { RESOLVE_CALL }, None);
        assert_eq!(unsafe { LOOKUP_CALL }, None);
    }

    #[test]
    fn failed_indirect_resolution_skips_lookup() {
        let mut source_marker = 0u8;
        let _bench = bench(1, core::ptr::null_mut(), core::ptr::null_mut());
        let table = vtable();
        let mut reference = reference(
            &table,
            &mut source_marker,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        assert_eq!(unsafe { resource_reference_value(&mut reference) }, 0);
        let resolve_call = unsafe { RESOLVE_CALL }.expect("missing indirect resolution");
        assert_eq!(resolve_call.0, &mut reference as *mut _);
        assert_eq!(resolve_call.1, &mut source_marker as *mut u8);
        assert_eq!(unsafe { LOOKUP_CALL }, None);
    }

    #[test]
    fn missing_index_record_returns_zero_after_lookup() {
        let mut index_marker = 0u8;
        let mut direct_entry_marker = 0u8;
        let _bench = bench(1, core::ptr::null_mut(), core::ptr::null_mut());
        let table = vtable();
        let mut context = context((&mut index_marker as *mut u8).cast());
        let mut reference = reference(
            &table,
            core::ptr::null_mut(),
            (&mut direct_entry_marker as *mut u8).cast(),
            &mut context,
        );

        assert_eq!(unsafe { resource_reference_value(&mut reference) }, 0);
        assert_eq!(
            unsafe { LOOKUP_CALL },
            Some(((&mut index_marker as *mut u8).cast(), (&mut direct_entry_marker as *mut u8).cast()))
        );
    }
}
