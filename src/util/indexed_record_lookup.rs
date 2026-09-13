//! `indexed_record_lookup` — original: `FUN_080ffae8` @ `0x080ffae8` (68
//! bytes: 60 instruction bytes plus the two 4-byte literal-pool words at
//! `0x080ffb24` and `0x080ffb28`; the next separately linked function begins
//! at `0x080ffb2c`).
//!
//! Raw decoding of every ARM B/BL word in `osos.dec` finds exactly seven
//! direct callers, all unconditional `bl` (at `0x080ffb90`, `0x0819ae84`,
//! `0x0819afb4`, `0x08203b6c`, `0x08203c44`, `0x08203c80`, and `0x08203dc0`);
//! there are no predicated calls or direct tail branches. The callers use the
//! returned pointer as a record with fields at +0x04, +0x0a, +0x0c, +0x0e,
//! and +0x10, but the record's concrete class is not identified.
//!
//! # Algorithm
//!
//! The lookup is enabled only when the word at `0x089cb44c` is nonzero and
//! accepts only the 205 unsigned indices `0..0xcd`. It loads the runtime
//! provider from the global slot at `0x08a78c70`, invokes the provider's
//! callback at +0x40 as `(provider_slot, index)`, then returns the pointer
//! stored in the callback's returned pointer cell. It does not guard either
//! the provider, callback, or result cell; those malformed states fault in
//! the retail body too.
//!
//! The callback identity is deliberately not invented: its target is runtime
//! data and does not decode as a static function entry. The host build uses
//! private mutable backing for the two fixed firmware globals so tests can
//! exercise the actual bounds check and structural dispatch; the target build
//! reads the verified absolute addresses.

/// The exclusive upper bound enforced by the original `cmp r0,#0xcd` / `movcs`.
const INDEX_LIMIT: u32 = 0xcd;

/// The enabled word is the second word of the runtime lookup state.
const LOOKUP_ENABLED_ADDRESS: usize = 0x089c_b44c;

/// Runtime global that stores the provider pointer and is passed by address to
/// its callback.
const PROVIDER_SLOT_ADDRESS: usize = 0x08a7_8c70;

/// A provider whose +0x40 callback resolves an index to a pointer cell.
///
/// The prefix deliberately consists of target-width words, so the callback
/// remains at byte offset +0x40 on both ARM and 64-bit host test builds.
#[repr(C)]
pub struct IndexedRecordProvider {
    /// +0x00..+0x3c: provider state not read by this wrapper.
    pub unresolved_00_3c: [u32; 16],
    /// +0x40: runtime callback; its static identity is unresolved.
    pub lookup: unsafe extern "C" fn(
        provider_slot: *mut *mut IndexedRecordProvider,
        index: u32,
    ) -> *const *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x40] = [0; core::mem::offset_of!(IndexedRecordProvider, lookup)];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_enabled() -> u32 {
    unsafe { core::ptr::read_volatile(LOOKUP_ENABLED_ADDRESS as *const u32) }
}

#[cfg(not(target_os = "none"))]
static mut HOST_LOOKUP_ENABLED: u32 = 0;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_enabled() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HOST_LOOKUP_ENABLED)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn provider_slot() -> *mut *mut IndexedRecordProvider {
    PROVIDER_SLOT_ADDRESS as *mut *mut IndexedRecordProvider
}

#[cfg(not(target_os = "none"))]
static mut HOST_PROVIDER_SLOT: *mut IndexedRecordProvider = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn provider_slot() -> *mut *mut IndexedRecordProvider {
    core::ptr::addr_of_mut!(HOST_PROVIDER_SLOT)
}

/// indexed_record_lookup — original: `FUN_080ffae8` @ `0x080ffae8` (68 bytes).
///
/// Returns the record pointer resolved by the runtime provider for `index`, or
/// null when the global lookup state is disabled or `index >= 205`.
///
/// # Safety
///
/// When lookup is enabled, the provider slot must point to an
/// [`IndexedRecordProvider`] with a valid +0x40 callback, and that callback
/// must return a valid pointer cell. The retail function has no guards for
/// those three dereferences.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_record_lookup(index: u32) -> *mut u8 {
    if unsafe { lookup_enabled() } == 0 {
        return core::ptr::null_mut();
    }
    if index >= INDEX_LIMIT {
        return core::ptr::null_mut();
    }

    let provider_slot = unsafe { provider_slot() };
    let provider = unsafe { core::ptr::read_volatile(provider_slot) };
    let lookup = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!((*provider).lookup))
    };
    let record_cell = unsafe { lookup(provider_slot, index) };
    unsafe { core::ptr::read_volatile(record_cell) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOOKUP_TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut MOCK_CALLS: u32 = 0;
    static mut MOCK_SLOT: *mut *mut IndexedRecordProvider = core::ptr::null_mut();
    static mut MOCK_INDEX: u32 = 0;
    static mut MOCK_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_lookup(
        provider_slot: *mut *mut IndexedRecordProvider,
        index: u32,
    ) -> *const *mut u8 {
        unsafe {
            MOCK_CALLS += 1;
            MOCK_SLOT = provider_slot;
            MOCK_INDEX = index;
            core::ptr::addr_of!(MOCK_RESULT)
        }
    }

    unsafe fn reset_host_state() {
        unsafe {
            core::ptr::addr_of_mut!(HOST_LOOKUP_ENABLED).write_volatile(0);
            core::ptr::addr_of_mut!(HOST_PROVIDER_SLOT).write_volatile(core::ptr::null_mut());
            MOCK_CALLS = 0;
            MOCK_SLOT = core::ptr::null_mut();
            MOCK_INDEX = 0;
            MOCK_RESULT = core::ptr::null_mut();
        }
    }

    fn provider() -> IndexedRecordProvider {
        IndexedRecordProvider {
            unresolved_00_3c: [0; 16],
            lookup: recording_lookup,
        }
    }

    #[test]
    fn disabled_lookup_and_out_of_range_index_skip_every_dereference() {
        let _guard = LOOKUP_TEST_LOCK.lock();
        unsafe { reset_host_state() };

        assert!(unsafe { indexed_record_lookup(0) }.is_null());
        assert_eq!(unsafe { MOCK_CALLS }, 0);

        let mut provider = provider();
        unsafe {
            core::ptr::addr_of_mut!(HOST_LOOKUP_ENABLED).write_volatile(1);
            core::ptr::addr_of_mut!(HOST_PROVIDER_SLOT).write_volatile(&mut provider);
        }
        assert!(unsafe { indexed_record_lookup(INDEX_LIMIT) }.is_null());
        assert_eq!(unsafe { MOCK_CALLS }, 0);
    }

    #[test]
    fn valid_boundary_indices_return_callback_cell_value_and_slot() {
        let _guard = LOOKUP_TEST_LOCK.lock();
        unsafe { reset_host_state() };
        let mut provider = provider();
        let mut first_record = [0u8; 20];
        let mut last_record = [0u8; 20];
        unsafe {
            core::ptr::addr_of_mut!(HOST_LOOKUP_ENABLED).write_volatile(1);
            core::ptr::addr_of_mut!(HOST_PROVIDER_SLOT).write_volatile(&mut provider);
            MOCK_RESULT = first_record.as_mut_ptr();
        }

        assert_eq!(unsafe { indexed_record_lookup(0) }, first_record.as_mut_ptr());
        assert_eq!(unsafe { MOCK_CALLS }, 1);
        assert_eq!(unsafe { MOCK_SLOT }, core::ptr::addr_of_mut!(HOST_PROVIDER_SLOT));
        assert_eq!(unsafe { MOCK_INDEX }, 0);

        unsafe { MOCK_RESULT = last_record.as_mut_ptr() };
        assert_eq!(unsafe { indexed_record_lookup(INDEX_LIMIT - 1) }, last_record.as_mut_ptr());
        assert_eq!(unsafe { MOCK_CALLS }, 2);
        assert_eq!(unsafe { MOCK_SLOT }, core::ptr::addr_of_mut!(HOST_PROVIDER_SLOT));
        assert_eq!(unsafe { MOCK_INDEX }, INDEX_LIMIT - 1);
    }
}
