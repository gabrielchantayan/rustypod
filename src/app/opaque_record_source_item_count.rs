//! `opaque_record_source_item_count` — original: `FUN_082841f8` @ `0x082841f8`
//! (**28 bytes**, `0x082841f8..0x08284210`; the next separately linked function
//! starts at `0x08284214`).
//!
//! Raw ARM is `mov r1,r0; ldr r0,[r0]; cmp r0,#0; ldrhne r1,[r1,#26];
//! mvneq r0,#0; bne 0x081c1ee0; bx lr`. A null provider returns `-1`; otherwise
//! the source's signed 16-bit selector is forwarded to the unported retailOS
//! helper at `0x081c1ee0`, whose result is returned unchanged.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds **seven direct plain
//! unconditional `bl` call sites**, at `0x081a1b68`, `0x081a1bdc`,
//! `0x081a1d68`, `0x081a1df0`, `0x081a1e64`, `0x081a1fd0`, and `0x08284458`;
//! there are no predicated `bl` call sites or direct tail branches.
//!
//! Deliberate deviation: `FUN_081c1ee0` is not yet ported. Target builds call
//! its fixed retailOS address; host tests install a volatile dispatch seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_RECORD_SOURCE_ITEM_COUNT: usize = 0x081c_1ee0;

/// The recovered 28-byte record-source prefix.
///
/// `provider` is a target-width pointer, so it remains `u32` on 64-bit host
/// tests. Only the selector at `+0x1a` is interpreted by this function.
#[repr(C)]
pub struct OpaqueRecordSource {
    pub provider: u32,
    pub opaque_04_to_14: [u32; 5],
    pub opaque_18: u8,
    pub opaque_19: u8,
    pub selector: i16,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(OpaqueRecordSource, provider)];
const _: [u8; 0x1a] = [0; core::mem::offset_of!(OpaqueRecordSource, selector)];
const _: [u8; 0x1c] = [0; core::mem::size_of::<OpaqueRecordSource>()];

/// ABI of the unported record-source helper at `0x081c1ee0`.
pub type RecordSourceItemCount = unsafe extern "C" fn(*mut u8, i32) -> i32;

/// Host operations for the unported record-source helper.
#[derive(Clone, Copy)]
pub struct RecordSourceItemCountOps {
    pub item_count: RecordSourceItemCount,
}

#[cfg(target_os = "none")]
unsafe fn retail_record_source_item_count(provider: *mut u8, selector: i32) -> i32 {
    let item_count: RecordSourceItemCount = core::mem::transmute(RETAIL_RECORD_SOURCE_ITEM_COUNT);
    item_count(provider, selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_source_item_count(_provider: *mut u8, _selector: i32) -> i32 {
    panic!("install record-source item-count host operations before calling this wrapper")
}

/// Host default before a test installs the retail helper equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_RECORD_SOURCE_ITEM_COUNT_OPS: RecordSourceItemCountOps = RecordSourceItemCountOps {
    item_count: missing_record_source_item_count,
};

/// Host-side helper seam. Target builds always call `0x081c1ee0`.
#[cfg(not(target_os = "none"))]
pub static mut RECORD_SOURCE_ITEM_COUNT_OPS: RecordSourceItemCountOps =
    DEFAULT_RECORD_SOURCE_ITEM_COUNT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_record_source_item_count(provider: *mut u8, selector: i32) -> i32 {
    let item_count = core::ptr::read_volatile(addr_of!(RECORD_SOURCE_ITEM_COUNT_OPS.item_count));
    item_count(provider, selector)
}

/// Returns the item count reported by the source's provider, or `-1` when the
/// provider word is null.
///
/// Original: `FUN_082841f8` @ `0x082841f8` (28 bytes; seven unconditional
/// direct `bl` call sites, binary-scanned). The selector is sign-extended from
/// the source's halfword at `+0x1a`; no source-pointer guard exists.
///
/// # Safety
///
/// `source` must identify readable, aligned [`OpaqueRecordSource`] storage.
/// When `source.provider` is nonzero it must identify a provider accepted by
/// retailOS `FUN_081c1ee0`; the wrapper adds no validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_source_item_count")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_source_item_count(source: *const OpaqueRecordSource) -> i32 {
    let provider = (*source).provider;
    if provider == 0 {
        return -1;
    }

    let selector = (*source).selector as i32;
    #[cfg(target_os = "none")]
    return retail_record_source_item_count(provider as usize as *mut u8, selector);
    #[cfg(not(target_os = "none"))]
    return host_record_source_item_count(provider as usize as *mut u8, selector);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    static PROVIDER_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_RECORD_SOURCE_ITEM_COUNT, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALL: Option<(*mut u8, i32)> = None;
    static mut DISPATCH_RESULT: i32 = 0;

    unsafe extern "C" fn record_item_count(provider: *mut u8, selector: i32) -> i32 {
        DISPATCH_CALL = Some((provider, selector));
        DISPATCH_RESULT
    }

    fn install_recorder(result: i32) -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(DISPATCH_CALL).write(None);
            addr_of_mut!(DISPATCH_RESULT).write(result);
            addr_of_mut!(RECORD_SOURCE_ITEM_COUNT_OPS).write(RecordSourceItemCountOps {
                item_count: record_item_count,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(RECORD_SOURCE_ITEM_COUNT_OPS).write(DEFAULT_RECORD_SOURCE_ITEM_COUNT_OPS);
        }
        drop(guard);
    }

    #[test]
    fn null_provider_returns_negative_one_without_dispatching() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let source = OpaqueRecordSource {
            provider: 0,
            opaque_04_to_14: [0; 5],
            opaque_18: 0xaa,
            opaque_19: 0xbb,
            selector: -1,
        };

        assert_eq!(unsafe { opaque_record_source_item_count(&source) }, -1);
    }

    #[test]
    fn forwards_mapped_provider_and_sign_extended_selector() {
        let guard = install_recorder(-0x1234);
        let Some(provider) = *PROVIDER_FIXTURE else {
            restore_default(guard);
            assert!(note_missing_u32_fixture("app::opaque_record_source_item_count"));
            return;
        };
        let provider = provider as *mut u8;
        unsafe {
            provider.write(0xa5);
            let source = OpaqueRecordSource {
                provider: provider as usize as u32,
                opaque_04_to_14: [0; 5],
                opaque_18: 0,
                opaque_19: 0,
                selector: i16::MIN,
            };

            assert_eq!(opaque_record_source_item_count(&source), -0x1234);
            assert_eq!(addr_of!(DISPATCH_CALL).read(), Some((provider, -32_768)));
        }
        restore_default(guard);
    }
}
