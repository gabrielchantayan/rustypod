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
}
