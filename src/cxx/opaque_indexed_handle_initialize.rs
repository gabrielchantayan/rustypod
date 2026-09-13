//! Initialize an opaque indexed handle — retailOS `FUN_0813e624` at load
//! address `0x0813e624` (64 bytes).
//!
//! Raw ARM establishes the exact extent: `push {r2-r6,lr}` opens at
//! `0x0813e624`; `pop {r2-r6,pc}` closes at `0x0813e660`; the next separately
//! linked function opens at `0x0813e664`. Decoding every ARM B/BL-immediate
//! word in `osos.dec` finds six direct callers, all unconditional plain `bl`
//! (`0x081433fc`, `0x0814a950`, `0x081b7630`, `0x0822411c`, `0x0829df58`, and
//! `0x082c8548`); no predicated call reaches this function.
//!
//! The wrapper clears the output pointer and tag byte, obtains an entry from
//! the source's opaque indexed provider at +0x40 using the supplied unsigned
//! index, then writes the result and a zero tag to the five-byte output
//! handle. The provider helper at `0x08052560` is still unported: on target
//! it is called at that retailOS load address, while hosts use a replaceable
//! seam. The concrete provider and entry types are not recoverable from the
//! decrypted bytes, so this port deliberately keeps both opaque.
//!
//! Deliberate deviation: host handles use a native-width pointer, placing the
//! tag after it rather than at target byte offset +4; ARM's `repr(C)` layout is
//! exactly the retail five-byte `{u32, u8}` record. Volatile accesses preserve
//! the retail clear-before-lookup and result-copy ordering.

/// Opaque five-byte target handle populated by [`opaque_indexed_handle_initialize`].
#[repr(C)]
pub struct OpaqueIndexedHandle {
    pub entry: *mut u8,
    pub tag: u8,
}

/// Source object whose only recovered field is its indexed provider at +0x40.
#[repr(C)]
pub struct OpaqueIndexedHandleSource {
    _unknown_prefix: [u32; 16],
    pub indexed_provider: *mut u8,
}

type IndexedProviderLookup = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_indexed_provider(provider: *mut u8, index: u32) -> *mut u8 {
    let lookup: IndexedProviderLookup = core::mem::transmute(0x0805_2560usize);
    lookup(provider, index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_indexed_provider_lookup(_provider: *mut u8, _index: u32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Host boundary for the unported indexed-provider lookup at `0x08052560`.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_INDEXED_PROVIDER_LOOKUP: IndexedProviderLookup = unavailable_indexed_provider_lookup;

/// Serializes host tests that replace [`OPAQUE_INDEXED_PROVIDER_LOOKUP`].
#[cfg(test)]
pub(crate) static OPAQUE_INDEXED_PROVIDER_LOOKUP_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_indexed_provider(provider: *mut u8, index: u32) -> *mut u8 {
    let lookup = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_INDEXED_PROVIDER_LOOKUP));
    lookup(provider, index)
}

/// opaque_indexed_handle_initialize — original: `FUN_0813e624` @ `0x0813e624`
/// (64 bytes; six unconditional direct `bl` call sites).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_indexed_handle_initialize")]
#[inline(never)]
pub unsafe extern "C" fn opaque_indexed_handle_initialize(
    output: *mut OpaqueIndexedHandle,
    source: *const OpaqueIndexedHandleSource,
    index: u32,
) {
    core::ptr::addr_of_mut!((*output).entry).write_volatile(core::ptr::null_mut());
    core::ptr::addr_of_mut!((*output).tag).write_volatile(0);

    let provider = core::ptr::addr_of!((*source).indexed_provider).read_volatile();
    let entry = lookup_indexed_provider(provider, index);

    core::ptr::addr_of_mut!((*output).entry).write_volatile(entry);
    core::ptr::addr_of_mut!((*output).tag).write_volatile(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_PROVIDER: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RECORDED_INDEX: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RETURN_ENTRY: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_lookup(provider: *mut u8, index: u32) -> *mut u8 {
        CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        RECORDED_PROVIDER.store(provider as usize, Ordering::SeqCst);
        RECORDED_INDEX.store(index as usize, Ordering::SeqCst);
        RETURN_ENTRY.load(Ordering::SeqCst) as *mut u8
    }

    struct HostLookupReset;

    impl Drop for HostLookupReset {
        fn drop(&mut self) {
            unsafe { OPAQUE_INDEXED_PROVIDER_LOOKUP = unavailable_indexed_provider_lookup };
        }
    }

    fn install_lookup(entry: *mut u8) -> HostLookupReset {
        CALL_COUNT.store(0, Ordering::SeqCst);
        RECORDED_PROVIDER.store(usize::MAX, Ordering::SeqCst);
        RECORDED_INDEX.store(usize::MAX, Ordering::SeqCst);
        RETURN_ENTRY.store(entry as usize, Ordering::SeqCst);
        unsafe { OPAQUE_INDEXED_PROVIDER_LOOKUP = record_lookup };
        HostLookupReset
    }

    #[test]
    fn initializes_handle_from_provider_entry_at_maximum_index() {
        let _guard = OPAQUE_INDEXED_PROVIDER_LOOKUP_TEST_LOCK.lock();
        let provider = 0x1234_5000usize as *mut u8;
        let entry = 0x5678_9000usize as *mut u8;
        let _reset = install_lookup(entry);
        let source = OpaqueIndexedHandleSource {
            _unknown_prefix: [0; 16],
            indexed_provider: provider,
        };
        let mut output = OpaqueIndexedHandle {
            entry: 0xdead_beefusize as *mut u8,
            tag: u8::MAX,
        };

        unsafe { opaque_indexed_handle_initialize(&mut output, &source, u32::MAX) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_PROVIDER.load(Ordering::SeqCst), provider as usize);
        assert_eq!(RECORDED_INDEX.load(Ordering::SeqCst), u32::MAX as usize);
        assert_eq!(output.entry, entry);
        assert_eq!(output.tag, 0);
    }

    #[test]
    fn null_provider_result_replaces_existing_entry_and_clears_tag() {
        let _guard = OPAQUE_INDEXED_PROVIDER_LOOKUP_TEST_LOCK.lock();
        let provider = 0x2468_0000usize as *mut u8;
        let _reset = install_lookup(core::ptr::null_mut());
        let source = OpaqueIndexedHandleSource {
            _unknown_prefix: [u32::MAX; 16],
            indexed_provider: provider,
        };
        let mut output = OpaqueIndexedHandle {
            entry: 0xface_cafeusize as *mut u8,
            tag: 7,
        };

        unsafe { opaque_indexed_handle_initialize(&mut output, &source, 0) };

        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_PROVIDER.load(Ordering::SeqCst), provider as usize);
        assert_eq!(RECORDED_INDEX.load(Ordering::SeqCst), 0);
        assert!(output.entry.is_null());
        assert_eq!(output.tag, 0);
    }
}
