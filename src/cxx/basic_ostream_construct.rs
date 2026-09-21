//! Constructor for retailOS's `basic_ostream`-compatible stream record.
//!
//! ## Original: `FUN_082a7818` @ 0x082a7818 (76 bytes)
//!
//! Raw ARM proves 72 instruction bytes through `pop {r4,r5,r6,pc}` at
//! `0x082a7860`, followed by the descriptor literal at `0x082a7864`; the next
//! real function begins at `0x082a7868`. There are three inbound plain `bl`
//! sites (`0x082a8f2c`, `0x082a8f54`, and `0x082a8f74`), no inbound predicated
//! `bl` sites, and two outbound plain `bl` calls: the shared-handle constructor
//! and `basic_ios_initialize`.
//!
//! It installs its initial descriptor, constructs the embedded shared-handle
//! record at +0x04, reinstalls the final descriptor, stores its secondary
//! descriptor word at the vtable-selected `basic_ios` base, initializes that
//! base with the supplied stream buffer, then returns the containing record.
//! Host builds use a fixture-only `basic_ios` base because the target
//! descriptor is an absolute firmware pointer and cannot be dereferenced on a
//! host; target builds read the descriptor-selected offset exactly as ARM does.

use crate::cxx::basic_ios_initialize::basic_ios_initialize;
use crate::cxx::vtable_shared_handle_construct::{vtable_shared_handle_construct, VtableSharedHandle};

const BASIC_OSTREAM_DESCRIPTOR: u32 = 0x089a_8624;
const HOST_BASIC_IOS_OFFSET: usize = 64;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn basic_ios_offset() -> usize {
    unsafe { ((BASIC_OSTREAM_DESCRIPTOR as *const i32).sub(3)).read() as usize }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
const fn basic_ios_offset() -> usize {
    HOST_BASIC_IOS_OFFSET
}

/// `basic_ostream_construct` — original `FUN_082a7818` @ `0x082a7818`.
///
/// # Safety
///
/// `storage` must be valid for the target's 0x44-byte stream record. Its
/// descriptor-selected `basic_ios` subobject and the embedded shared-handle
/// record at +0x04 must meet the requirements of their respective constructors.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.basic_ostream_construct")]
#[inline(never)]
pub unsafe extern "C" fn basic_ostream_construct(storage: *mut u8, streambuf: u32) -> *mut u8 {
    unsafe {
        storage.cast::<u32>().write(BASIC_OSTREAM_DESCRIPTOR);
        vtable_shared_handle_construct(storage.add(4).cast::<VtableSharedHandle>());
        storage.cast::<u32>().write(BASIC_OSTREAM_DESCRIPTOR);

        let basic_ios = storage.add(basic_ios_offset());
        basic_ios.cast::<u32>().write(BASIC_OSTREAM_DESCRIPTOR);
        basic_ios_initialize(basic_ios, streambuf);
        storage
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::basic_ios_initialize::{
        BasicIosInitializeOps, BASIC_IOS_FACET_ID, BASIC_IOS_INITIALIZE_OPS, BASIC_IOS_INITIALIZE_TEST_LOCK,
    };
    use crate::cxx::shared_handle_initialize::{
        SHARED_HANDLE_BOOTSTRAP, SHARED_HANDLE_GLOBAL, SHARED_HANDLE_INITIALIZE_TEST_LOCK,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x400;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BASIC_OSTREAM_CONSTRUCT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    unsafe extern "C" fn widen_space(_facet: u32, _character: u32) -> u8 {
        0x7e
    }

    unsafe extern "C" fn unexpected_slow_lookup(
        _locale: *mut u32,
        _facet_id: *const u32,
        _direction: u32,
        _character: u32,
        _descriptor: usize,
    ) -> u32 {
        panic!("fixture supplies the requested facet")
    }

    unsafe extern "C" fn release_locale(_locale: *mut u32) {}

    unsafe extern "C" fn unexpected_bootstrap() {
        panic!("fixture supplies a shared object")
    }

    #[test]
    fn constructs_embedded_handle_and_basic_ios_subobject() {
        let _ios_lock = BASIC_IOS_INITIALIZE_TEST_LOCK.lock();
        let _shared_lock = SHARED_HANDLE_INITIALIZE_TEST_LOCK.lock();
        unsafe {
            let Some(base) = *SLAB else {
                assert!(note_missing_u32_fixture("cxx/basic_ostream_construct"));
                return;
            };
            let base = base as *mut u8;
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            let locale = base.add(0x100).cast::<u32>();
            let facet_table = base.add(0x200).cast::<u32>();
            let shared_object = base.add(0x300).cast::<u32>();
            locale.add(2).write(facet_table as usize as u32);
            locale.add(3).write(1);
            locale.add(7).write(0);
            facet_table.write(0x1234_5678);
            shared_object.add(7).write(0);
            SHARED_HANDLE_GLOBAL = shared_object as usize as u32;
            SHARED_HANDLE_BOOTSTRAP = unexpected_bootstrap;
            BASIC_IOS_FACET_ID = 0;
            BASIC_IOS_INITIALIZE_OPS = BasicIosInitializeOps {
                slow_facet_lookup: unexpected_slow_lookup,
                facet_widen: widen_space,
                locale_handle_release: release_locale,
            };
            base.add(HOST_BASIC_IOS_OFFSET + 24).cast::<u32>().write(locale as usize as u32);

            assert_eq!(basic_ostream_construct(base, 0xa5a5_5a5a), base);
            assert_eq!(base.cast::<u32>().read(), BASIC_OSTREAM_DESCRIPTOR);
            assert_eq!(base.add(HOST_BASIC_IOS_OFFSET).cast::<u32>().read(), BASIC_OSTREAM_DESCRIPTOR);
            assert_eq!(base.add(HOST_BASIC_IOS_OFFSET + 4).cast::<u32>().read(), 0x1002);
            assert_eq!(base.add(HOST_BASIC_IOS_OFFSET + 52).cast::<u32>().read(), 0xa5a5_5a5a);
            assert_eq!(base.add(HOST_BASIC_IOS_OFFSET + 60).read(), 0x7e);
            assert_eq!(shared_object.add(7).read(), 1);
        }
    }
}
