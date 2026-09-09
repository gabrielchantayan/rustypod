//! `load_resource_list` — original: `FUN_08184fd4` @ 0x08184fd4 (76 bytes:
//! 72 instruction bytes plus the literal-pool vtable word at 0x0818501c;
//! the next function begins at 0x08185020). Raw decoding of every ARM B/BL
//! word in `osos.dec` finds 19 direct call sites: all are unconditional `bl`;
//! there are no predicated calls, tail branches, or data-word occurrences.
//!
//! # Algorithm
//!
//! Builds the 0x24-byte resource-list owner that the `ptr_vector_*` helpers
//! address. It plants vtable `0x08989508`, clears the embedded three-word
//! pointer vector at +0x14 through the already ported
//! `three_word_clear_seventh` (`FUN_083e472c`), then forwards the owner and
//! its four remaining ABI words to `FUN_08184f50`. That initializer writes the
//! provider, resource-data, parser words, and flags; when its provider is
//! nonzero it loads the requested resource records into the vector.
//!
//! # Deviations
//!
//! `FUN_08184f50` is not ported, so the target default calls its verified
//! firmware address directly while host tests substitute `RESOURCE_LIST_OPS`.
//! This preserves the original call boundary and makes the pre-initializer
//! vtable/vector state observable. Ghidra's extra arguments to
//! `FUN_083e472c` are phantom: raw ARM passes only `this + 0x14` in r0.

use crate::cxx::three_word_clear_seventh::three_word_clear_seventh;

/// The vtable literal loaded from the pool word at `0x0818501c`.
pub const RESOURCE_LIST_VTABLE_ADDRESS: u32 = 0x0898_9508;

/// A loaded resource list's complete 0x24-byte ARM layout.
///
/// The pointer-like fields deliberately remain `u32`: they are target words,
/// not host pointers, and the retail initializer stores them at fixed offsets.
#[repr(C)]
pub struct ResourceList {
    /// +0x00: vtable set before either initializer call.
    pub vtable: u32,
    /// +0x04: provider forwarded in r1 to `FUN_08184f50`.
    pub provider: u32,
    /// +0x08: parser word forwarded in r3.
    pub parser: u32,
    /// +0x0c: resource-data word forwarded in r2.
    pub resource_data: u32,
    /// +0x10: cleared by `FUN_08184f50`.
    pub state: u32,
    /// +0x14..+0x1c: pointer vector cleared before `FUN_08184f50` runs.
    pub vector_words: [u32; 3],
    /// +0x20: cleared by `FUN_08184f50`.
    pub loading: u8,
    /// +0x21: low byte of the fifth ABI word.
    pub first_flag: u8,
    /// +0x22: another copy of the fifth ABI word's low byte.
    pub second_flag: u8,
    /// +0x23: not accessed by this constructor pair.
    pub unused_23: u8,
}

/// The unported field initializer `FUN_08184f50`.
pub type ResourceListInitialize = unsafe extern "C" fn(
    list: *mut ResourceList,
    provider: u32,
    resource_data: u32,
    parser: u32,
    options: u32,
);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_resource_list_initialize(
    list: *mut ResourceList,
    provider: u32,
    resource_data: u32,
    parser: u32,
    options: u32,
) {
    let initialize: ResourceListInitialize = unsafe { core::mem::transmute(0x0818_4f50usize) };
    unsafe { initialize(list, provider, resource_data, parser, options) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_list_initialize(
    _list: *mut ResourceList,
    _provider: u32,
    _resource_data: u32,
    _parser: u32,
    _options: u32,
) {
    panic!("load_resource_list requires resource-list initializer 0x08184f50")
}

/// Host-testable model of the one unported direct callee.
#[cfg(target_os = "none")]
pub const DEFAULT_RESOURCE_LIST_OPS: ResourceListInitialize = firmware_resource_list_initialize;
/// Host-testable model of the one unported direct callee.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_RESOURCE_LIST_OPS: ResourceListInitialize = missing_resource_list_initialize;

/// Active resource-list initializer. The target default calls retailOS;
/// host tests replace it to observe the exact constructor boundary.
pub static mut RESOURCE_LIST_OPS: ResourceListInitialize = DEFAULT_RESOURCE_LIST_OPS;

#[inline(always)]
unsafe fn resource_list_initialize() -> ResourceListInitialize {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_LIST_OPS)) }
}
/// The unported list-finalization helper `FUN_08184d08`.
pub type ResourceListBeforeDestroy = unsafe extern "C" fn(list: *mut ResourceList);

/// The unported dynamic-state destructor `FUN_08144000`.
pub type ResourceListStateDestroy = unsafe extern "C" fn(state: *mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_resource_list_before_destroy(list: *mut ResourceList) {
    let before_destroy: ResourceListBeforeDestroy =
        unsafe { core::mem::transmute(0x0818_4d08usize) };
    unsafe { before_destroy(list) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_list_before_destroy(_list: *mut ResourceList) {
    panic!("resource_list_destroy requires list finalizer 0x08184d08")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_resource_list_state_destroy(state: *mut u8) -> *mut u8 {
    let destroy: ResourceListStateDestroy = unsafe { core::mem::transmute(0x0814_4000usize) };
    unsafe { destroy(state) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_list_state_destroy(_state: *mut u8) -> *mut u8 {
    panic!("resource_list_destroy requires state destructor 0x08144000")
}

/// Active resource-list finalizer. The target default calls retailOS; host
/// tests replace it to observe the original flag-gated call boundary.
#[cfg(target_os = "none")]
pub static mut RESOURCE_LIST_BEFORE_DESTROY: ResourceListBeforeDestroy =
    firmware_resource_list_before_destroy;
/// Host default deliberately reports an unported direct call.
#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_LIST_BEFORE_DESTROY: ResourceListBeforeDestroy =
    missing_resource_list_before_destroy;

/// Active resource-list state destructor. The target default calls retailOS;
/// host tests replace it because `FUN_08144000` remains unported.
#[cfg(target_os = "none")]
pub static mut RESOURCE_LIST_STATE_DESTROY: ResourceListStateDestroy =
    firmware_resource_list_state_destroy;
/// Host default deliberately reports an unported direct call.
#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_LIST_STATE_DESTROY: ResourceListStateDestroy =
    missing_resource_list_state_destroy;

#[inline(always)]
unsafe fn resource_list_before_destroy() -> ResourceListBeforeDestroy {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_LIST_BEFORE_DESTROY)) }
}

#[inline(always)]
unsafe fn resource_list_state_destroy() -> ResourceListStateDestroy {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_LIST_STATE_DESTROY)) }
}

/// Calls the ported target vector-size instantiation. Host fixtures retain
/// 32-bit pointer words, so their count uses the identical target-word math.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resource_list_vector_count(list: *const ResourceList) -> u32 {
    use crate::cxx::templates::{vector_size_elem4_alias_78c4, VectorBounds};

    unsafe {
        vector_size_elem4_alias_78c4(
            core::ptr::addr_of!((*list).vector_words).cast::<VectorBounds>(),
        ) as u32
    }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resource_list_vector_count(list: *const ResourceList) -> u32 {
    unsafe {
        let begin = (*list).vector_words[0];
        let end = (*list).vector_words[1];
        (end.wrapping_sub(begin) as i32 >> 2) as u32
    }
}


/// resource_list_destroy — original: `FUN_08185038` @ `0x08185038`.
///
/// Verified extent is `0x08185038..0x081850f0` (184 bytes: 180 instruction
/// bytes plus the vtable literal at `0x081850ec`); Ghidra's 176-byte extent
/// is short. Raw decoding of every ARM B/BL in `osos.dec` finds 14 direct
/// `bl` call sites, all unconditional, and one tail `b` at `0x081d0d40`.
///
/// Replants vtable `0x08989508`; when both flags at +0x21/+0x22 are nonzero,
/// calls the unported list finalizer. It deletes every vector element, first
/// releasing each +0x08 payload through `free_wrapper` tag 0x33 when +0x22
/// is set; releases non-NULL +0x10 state through `FUN_08144000`; then
/// array-deallocates the vector backing allocation. Descriptor words remain
/// dangling, exactly as in retailOS.
///
/// Deliberate deviations: the two unported direct callees use volatile
/// host-test seams. The target calls the ported vector-size and heap helpers
/// directly; host vector fixtures use target-width arithmetic because their
/// embedded pointer words are narrower than host pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resource_list_destroy(list: *mut ResourceList) -> *mut ResourceList {
    use crate::heap::veneers::{cxx_array_dealloc, free_wrapper, operator_delete};

    unsafe {
        (*list).vtable = RESOURCE_LIST_VTABLE_ADDRESS;
        if (*list).first_flag != 0 && (*list).second_flag != 0 {
            resource_list_before_destroy()(list);
        }

        let mut index = 0u32;
        loop {
            let begin = (*list).vector_words[0];
            let count = resource_list_vector_count(list);
            if index >= count {
                break;
            }

            let entry = (begin as *mut u32).add(index as usize).read() as *mut u8;
            if (*list).second_flag != 0 {
                let payload = entry.cast::<u32>().add(2).read() as *mut u8;
                free_wrapper(payload, 0x33);
            }
            operator_delete(entry);
            index = index.wrapping_add(1);
        }

        let state = (*list).state as *mut u8;
        if !state.is_null() {
            operator_delete(resource_list_state_destroy()(state));
        }

        let begin = (*list).vector_words[0] as *mut u8;
        let capacity = (*list).vector_words[2];
        let capacity_count = (capacity.wrapping_sub(begin as u32) as i32 >> 2) as usize;
        cxx_array_dealloc(begin, capacity_count, 0);
    }
    list
}

/// load_resource_list — original: `FUN_08184fd4` @ 0x08184fd4 (76 bytes).
///
/// Initializes and returns `list`; `list` must be writable for 0x24 bytes.
/// The original has no NULL guard before its vtable or vector stores.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn load_resource_list(
    list: *mut ResourceList,
    provider: u32,
    resource_data: u32,
    parser: u32,
    options: u32,
) -> *mut ResourceList {
    unsafe {
        core::ptr::addr_of_mut!((*list).vtable).write(RESOURCE_LIST_VTABLE_ADDRESS);
        three_word_clear_seventh(core::ptr::addr_of_mut!((*list).vector_words).cast::<u32>());
        resource_list_initialize()(list, provider, resource_data, parser, options);
    }
    list
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static INIT_CALLS: AtomicU32 = AtomicU32::new(0);
    static SEEN_LIST: AtomicUsize = AtomicUsize::new(0);
    static SEEN_PROVIDER: AtomicU32 = AtomicU32::new(0);
    static SEEN_RESOURCE_DATA: AtomicU32 = AtomicU32::new(0);
    static SEEN_PARSER: AtomicU32 = AtomicU32::new(0);
    static SEEN_OPTIONS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn recording_initialize(
        list: *mut ResourceList,
        provider: u32,
        resource_data: u32,
        parser: u32,
        options: u32,
    ) {
        INIT_CALLS.fetch_add(1, Ordering::SeqCst);
        SEEN_LIST.store(list as usize, Ordering::SeqCst);
        SEEN_PROVIDER.store(provider, Ordering::SeqCst);
        SEEN_RESOURCE_DATA.store(resource_data, Ordering::SeqCst);
        SEEN_PARSER.store(parser, Ordering::SeqCst);
        SEEN_OPTIONS.store(options, Ordering::SeqCst);

        // These are the writes made by raw `FUN_08184f50`; checking its input
        // state before doing them proves the constructor's call ordering.
        unsafe {
            assert_eq!((*list).vtable, RESOURCE_LIST_VTABLE_ADDRESS);
            assert_eq!((*list).vector_words, [0, 0, 0]);
            (*list).provider = provider;
            (*list).parser = parser;
            (*list).resource_data = resource_data;
            (*list).state = 0;
            (*list).loading = 0;
            (*list).first_flag = options as u8;
            (*list).second_flag = options as u8;
        }
    }

    struct OpsRestore(ResourceListInitialize);

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(RESOURCE_LIST_OPS),
                    self.0,
                );
            }
        }
    }

    static DESTROY_CALLS: AtomicU32 = AtomicU32::new(0);
    static DESTROY_LIST: AtomicUsize = AtomicUsize::new(0);
    static STATE_DESTROY_INPUT: AtomicUsize = AtomicUsize::new(0);
    static FREES: Mutex<std::vec::Vec<(u32, u32)>> = Mutex::new(std::vec::Vec::new());
    static DESTROY_SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::RESOURCE_LIST_DESTROY, 0x1000)
            .map(|pointer| pointer as usize)
    });

    unsafe extern "C" fn recording_before_destroy(list: *mut ResourceList) {
        DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        DESTROY_LIST.store(list as usize, Ordering::SeqCst);
        assert_eq!(unsafe { (*list).vtable }, RESOURCE_LIST_VTABLE_ADDRESS);
    }

    unsafe extern "C" fn recording_state_destroy(state: *mut u8) -> *mut u8 {
        STATE_DESTROY_INPUT.store(state as usize, Ordering::SeqCst);
        state
    }

    unsafe extern "C" fn recording_free(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        FREES.lock().push((ptr as usize as u32, tag as u32));
    }

    struct DestroyOpsRestore {
        before_destroy: ResourceListBeforeDestroy,
        state_destroy: ResourceListStateDestroy,
        heap: crate::heap::veneers::HeapVeneerOps,
        default_heap: *mut crate::heap::types::HeapDescriptorDescriptor,
    }

    impl Drop for DestroyOpsRestore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RESOURCE_LIST_BEFORE_DESTROY)
                    .write_volatile(self.before_destroy);
                core::ptr::addr_of_mut!(RESOURCE_LIST_STATE_DESTROY)
                    .write_volatile(self.state_destroy);
                core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS)
                    .write_volatile(self.heap);
                core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
                    .write_volatile(self.default_heap);
            }
        }
    }

    unsafe fn install_destroy_ops() -> DestroyOpsRestore {
        let before_destroy = core::ptr::addr_of!(RESOURCE_LIST_BEFORE_DESTROY).read_volatile();
        let state_destroy = core::ptr::addr_of!(RESOURCE_LIST_STATE_DESTROY).read_volatile();
        let heap = core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read_volatile();
        let default_heap = core::ptr::addr_of!(crate::heap::types::DEFAULT_HEAP).read_volatile();
        let mut recording_heap = heap;
        recording_heap.free = recording_free;
        core::ptr::addr_of_mut!(RESOURCE_LIST_BEFORE_DESTROY)
            .write_volatile(recording_before_destroy);
        core::ptr::addr_of_mut!(RESOURCE_LIST_STATE_DESTROY)
            .write_volatile(recording_state_destroy);
        core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(recording_heap);
        core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
            .write_volatile(1usize as *mut crate::heap::types::HeapDescriptorDescriptor);
        DestroyOpsRestore { before_destroy, state_destroy, heap, default_heap }
    }

    #[test]
    fn initializes_vector_before_forwarding_all_four_words() {
        let _lock = TEST_LOCK.lock();
        let previous = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_LIST_OPS))
        };
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(RESOURCE_LIST_OPS),
                recording_initialize,
            );
        }
        let _restore = OpsRestore(previous);
        INIT_CALLS.store(0, Ordering::SeqCst);

        let mut list = ResourceList {
            vtable: 0xdead_beef,
            provider: 0xaaaa_aaaa,
            parser: 0xbbbb_bbbb,
            resource_data: 0xcccc_cccc,
            state: 0xdddd_dddd,
            vector_words: [0x1111_1111, 0x2222_2222, 0x3333_3333],
            loading: 0x44,
            first_flag: 0x55,
            second_flag: 0x66,
            unused_23: 0x77,
        };
        let result = unsafe {
            load_resource_list(
                &mut list,
                0,
                0x1020_3040,
                0xa1b2_c3d4,
                0xffff_ff80,
            )
        };

        assert_eq!(core::mem::size_of::<ResourceList>(), 0x24);
        assert_eq!(result, core::ptr::addr_of_mut!(list));
        assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_LIST.load(Ordering::SeqCst), result as usize);
        assert_eq!(SEEN_PROVIDER.load(Ordering::SeqCst), 0);
        assert_eq!(SEEN_RESOURCE_DATA.load(Ordering::SeqCst), 0x1020_3040);
        assert_eq!(SEEN_PARSER.load(Ordering::SeqCst), 0xa1b2_c3d4);
        assert_eq!(SEEN_OPTIONS.load(Ordering::SeqCst), 0xffff_ff80);
        assert_eq!(list.vtable, RESOURCE_LIST_VTABLE_ADDRESS);
        assert_eq!(list.provider, 0);
        assert_eq!(list.parser, 0xa1b2_c3d4);
        assert_eq!(list.resource_data, 0x1020_3040);
        assert_eq!(list.state, 0);
        assert_eq!(list.vector_words, [0, 0, 0]);
        assert_eq!(list.loading, 0);
        assert_eq!(list.first_flag, 0x80);
        assert_eq!(list.second_flag, 0x80);
        assert_eq!(list.unused_23, 0x77);
    }

    #[test]
    fn destroy_releases_payloads_entries_state_and_vector_in_order() {
        let _lock = TEST_LOCK.lock();
        let Some(base) = *DESTROY_SLAB else {
            crate::testing::note_missing_u32_fixture("util::resource_list::destroy");
            return;
        };
        let base = base as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, 0x1000);
        }
        let _restore = unsafe { install_destroy_ops() };
        DESTROY_CALLS.store(0, Ordering::SeqCst);
        DESTROY_LIST.store(0, Ordering::SeqCst);
        STATE_DESTROY_INPUT.store(0, Ordering::SeqCst);
        FREES.lock().clear();

        let entries = unsafe { base.add(0x100).cast::<u32>() };
        let first_entry = unsafe { base.add(0x200) };
        let second_entry = unsafe { base.add(0x220) };
        let first_payload = unsafe { base.add(0x300) };
        let second_payload = unsafe { base.add(0x320) };
        let state = unsafe { base.add(0x340) };
        unsafe {
            entries.write(first_entry as usize as u32);
            entries.add(1).write(second_entry as usize as u32);
            first_entry.add(8).cast::<u32>().write(first_payload as usize as u32);
            second_entry.add(8).cast::<u32>().write(second_payload as usize as u32);
        }

        let original_vector = [
            entries as usize as u32,
            unsafe { entries.add(2) as usize as u32 },
            unsafe { entries.add(4) as usize as u32 },
        ];
        let mut list = ResourceList {
            vtable: 0,
            provider: 0,
            parser: 0,
            resource_data: 0,
            state: state as usize as u32,
            vector_words: original_vector,
            loading: 0,
            first_flag: 1,
            second_flag: 1,
            unused_23: 0,
        };

        let result = unsafe { resource_list_destroy(&mut list) };

        assert_eq!(result, core::ptr::addr_of_mut!(list));
        assert_eq!(list.vtable, RESOURCE_LIST_VTABLE_ADDRESS);
        assert_eq!(list.vector_words, original_vector);
        assert_eq!(DESTROY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(DESTROY_LIST.load(Ordering::SeqCst), result as usize);
        assert_eq!(STATE_DESTROY_INPUT.load(Ordering::SeqCst), state as usize);
        assert_eq!(
            *FREES.lock(),
            std::vec![
                (first_payload as usize as u32, 0x33),
                (first_entry as usize as u32, 2),
                (second_payload as usize as u32, 0x33),
                (second_entry as usize as u32, 2),
                (state as usize as u32, 2),
                (entries as usize as u32, 2),
            ],
        );
    }

    #[test]
    fn destroy_calls_finalizer_only_when_both_flags_are_set() {
        let _lock = TEST_LOCK.lock();
        let _restore = unsafe { install_destroy_ops() };

        for (first_flag, second_flag, expected_calls) in
            [(0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 1)]
        {
            DESTROY_CALLS.store(0, Ordering::SeqCst);
            let mut list = ResourceList {
                vtable: 0,
                provider: 0,
                parser: 0,
                resource_data: 0,
                state: 0,
                vector_words: [0, 0, 0],
                loading: 0,
                first_flag,
                second_flag,
                unused_23: 0,
            };

            let result = unsafe { resource_list_destroy(&mut list) };

            assert_eq!(result, core::ptr::addr_of_mut!(list));
            assert_eq!(DESTROY_CALLS.load(Ordering::SeqCst), expected_calls);
            assert_eq!(list.vtable, RESOURCE_LIST_VTABLE_ADDRESS);
        }
    }
}
