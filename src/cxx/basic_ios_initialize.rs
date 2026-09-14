//! `basic_ios_initialize` — retailOS `FUN_083e77dc` @ **0x083e77dc**
//! (188 bytes).
//!
//! Raw ARM establishes a 188-byte extent: 172 instruction bytes from
//! `0x083e77dc` through `pop {r2,r3,r4,r5,r6,pc}` at `0x083e7888`, followed
//! by the three-word literal pool at `0x083e788c..0x083e7894`; the separately
//! linked `stream_state_set` begins at `0x083e7898`. Decoding every aligned
//! ARM `B`/`BL` immediate in `osos.dec` finds five inbound direct calls, all
//! unconditional plain `bl`: `0x082a7858`, `0x082a8fb0`, `0x083d80a8`,
//! `0x083d8100`, and `0x083daec8`. There are no predicated direct calls or
//! tail branches. Its three outbound dispatches are predicated `bleq`
//! `0x082a72c8`, a `blx` through a facet vtable +0x1c slot, and `bl`
//! `0x082a8ba0`.
//!
//! It initializes the basic stream formatting fields, records the streambuf
//! target pointer, retains the stream locale, obtains its configured facet
//! (using the slow lookup only when the direct facet-table entry is absent),
//! asks that facet to translate character `0x20`, releases the locale handle,
//! and records the resulting fill character. Target builds use the retail
//! slow lookup and opaque-handle release helpers plus the 32-bit vtable slot.
//! Host builds use explicit seams for those unported/dynamic boundaries; this
//! is the only deliberate deviation.

#[cfg(not(target_os = "none"))]
use core::ptr;

const RETAIL_FACET_ID: *const u32 = 0x08a0_fb9c as *const u32;
const RETAIL_SLOW_FACET_LOOKUP: usize = 0x082a_72c8;
const RETAIL_LOCALE_HANDLE_RELEASE: usize = 0x082a_8ba0;
const FALLBACK_FACET_DESCRIPTOR: usize = 0x083a_b368;
const DEFAULT_FLAGS: u32 = 0x1002;
const DEFAULT_PRECISION: u32 = 6;
const SPACE_CHARACTER: u32 = 0x20;

#[repr(C)]
struct BasicIosFields {
    _vptr: u32,
    flags: u32,
    precision: u32,
    width: u32,
    state: u32,
    exception_mask: u32,
    locale: u32,
    _between_locale_and_streambuf: [u32; 6],
    streambuf: u32,
    callback_state: u32,
    fill_character: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 4] = [(); core::mem::offset_of!(BasicIosFields, flags)];
#[cfg(target_pointer_width = "32")]
const _: [(); 8] = [(); core::mem::offset_of!(BasicIosFields, precision)];
#[cfg(target_pointer_width = "32")]
const _: [(); 16] = [(); core::mem::offset_of!(BasicIosFields, state)];
#[cfg(target_pointer_width = "32")]
const _: [(); 24] = [(); core::mem::offset_of!(BasicIosFields, locale)];
#[cfg(target_pointer_width = "32")]
const _: [(); 52] = [(); core::mem::offset_of!(BasicIosFields, streambuf)];
#[cfg(target_pointer_width = "32")]
const _: [(); 56] = [(); core::mem::offset_of!(BasicIosFields, callback_state)];
#[cfg(target_pointer_width = "32")]
const _: [(); 60] = [(); core::mem::offset_of!(BasicIosFields, fill_character)];

type SlowFacetLookup = unsafe extern "C" fn(*mut u32, *const u32, u32, u32, usize) -> u32;
type FacetWiden = unsafe extern "C" fn(u32, u32) -> u8;
type LocaleHandleRelease = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
pub struct BasicIosInitializeOps {
    pub slow_facet_lookup: SlowFacetLookup,
    pub facet_widen: FacetWiden,
    pub locale_handle_release: LocaleHandleRelease,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_slow_facet_lookup(
    _locale: *mut u32,
    _facet_id: *const u32,
    _direction: u32,
    _character: u32,
    _descriptor: usize,
) -> u32 {
    panic!("install basic-ios initializer host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_facet_widen(_facet: u32, _character: u32) -> u8 {
    panic!("install basic-ios initializer host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_locale_handle_release(_locale: *mut u32) {
    panic!("install basic-ios initializer host seams before calling this port")
}

/// Host boundaries for the unported slow lookup and locale release plus the
/// native-width replacement for the facet's target-width virtual slot.
#[cfg(not(target_os = "none"))]
pub static mut BASIC_IOS_INITIALIZE_OPS: BasicIosInitializeOps = BasicIosInitializeOps {
    slow_facet_lookup: missing_slow_facet_lookup,
    facet_widen: missing_facet_widen,
    locale_handle_release: missing_locale_handle_release,
};

/// Host replacement for the retail process-wide facet identifier word.
#[cfg(not(target_os = "none"))]
pub static mut BASIC_IOS_FACET_ID: u32 = 0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn facet_id() -> u32 {
    unsafe { RETAIL_FACET_ID.read() }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn facet_id() -> u32 {
    unsafe { ptr::read_volatile(ptr::addr_of!(BASIC_IOS_FACET_ID)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn slow_facet_lookup(locale: *mut u32) -> u32 {
    let lookup: SlowFacetLookup = unsafe { core::mem::transmute(RETAIL_SLOW_FACET_LOOKUP) };
    unsafe { lookup(locale, RETAIL_FACET_ID, 1, SPACE_CHARACTER, FALLBACK_FACET_DESCRIPTOR) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn slow_facet_lookup(locale: *mut u32) -> u32 {
    let lookup = unsafe { ptr::read_volatile(ptr::addr_of!(BASIC_IOS_INITIALIZE_OPS.slow_facet_lookup)) };
    unsafe { lookup(locale, ptr::addr_of!(BASIC_IOS_FACET_ID), 1, SPACE_CHARACTER, FALLBACK_FACET_DESCRIPTOR) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn facet_widen(facet: u32) -> u8 {
    let vtable = unsafe { (facet as usize as *const u32).read() };
    let widen: FacetWiden = unsafe { core::mem::transmute((vtable as usize as *const u32).add(7).read()) };
    unsafe { widen(facet, SPACE_CHARACTER) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn facet_widen(facet: u32) -> u8 {
    let widen = unsafe { ptr::read_volatile(ptr::addr_of!(BASIC_IOS_INITIALIZE_OPS.facet_widen)) };
    unsafe { widen(facet, SPACE_CHARACTER) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_locale_handle(locale: *mut u32) {
    let release: LocaleHandleRelease = unsafe { core::mem::transmute(RETAIL_LOCALE_HANDLE_RELEASE) };
    unsafe { release(locale) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_locale_handle(locale: *mut u32) {
    let release = unsafe { ptr::read_volatile(ptr::addr_of!(BASIC_IOS_INITIALIZE_OPS.locale_handle_release)) };
    unsafe { release(locale) }
}

/// Initializes a basic stream's formatting state and locale-derived fill
/// character.
///
/// # Safety
///
/// `stream` must point to a writable `basic_ios`-compatible object. Its
/// +0x18 locale target pointer must designate a writable locale with words
/// +0x08 (facet table), +0x0c (facet count), and +0x1c (reference count). A
/// present facet table entry, or the slow lookup result, must be valid for its
/// target vtable's +0x1c callback. The original contains no NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.basic_ios_initialize")]
#[inline(never)]
pub unsafe extern "C" fn basic_ios_initialize(stream: *mut u8, streambuf: u32) {
    let fields = stream.cast::<BasicIosFields>();
    unsafe {
        (*fields).streambuf = streambuf;
        (*fields).state = if streambuf < 2 { 1 - streambuf } else { 0 };
        (*fields).callback_state = 0;
        (*fields).exception_mask = 0;
        (*fields).width = 0;
        (*fields).precision = DEFAULT_PRECISION;
        (*fields).flags = DEFAULT_FLAGS;

        let mut locale = (*fields).locale;
        let locale_words = locale as usize as *mut u32;
        let reference_count = locale_words.add(7).read();
        locale_words.add(7).write(reference_count.wrapping_add(1));

        let id = facet_id();
        let mut facet = if id < locale_words.add(3).read() {
            let table = locale_words.add(2).read() as usize as *const u32;
            table.add(id as usize).read()
        } else {
            0
        };
        if facet == 0 {
            facet = slow_facet_lookup(&mut locale);
        }
        (*fields).fill_character = facet_widen(facet);
        release_locale_handle(&mut locale);
    }
}

#[cfg(test)]
pub static BASIC_IOS_INITIALIZE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const LOCALE_OFFSET: usize = 0x100;
    const TABLE_OFFSET: usize = 0x200;
    const DIRECT_FACET: u32 = 0x1234_5678;
    const FALLBACK_FACET: u32 = 0x8765_4321;
    const FACET_ID: u32 = 2;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STREAM_BASIC_IOS_INITIALIZE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static SLOW_CALLS: AtomicU32 = AtomicU32::new(0);
    static WIDEN_FACET: AtomicU32 = AtomicU32::new(0);
    static WIDEN_CHARACTER: AtomicU32 = AtomicU32::new(0);
    static RELEASED_LOCALE: AtomicU32 = AtomicU32::new(0);
    static SEEN_SLOW_LOCALE: AtomicUsize = AtomicUsize::new(0);
    static SEEN_SLOW_LOCALE_VALUE: AtomicU32 = AtomicU32::new(0);
    static SEEN_SLOW_ID: AtomicUsize = AtomicUsize::new(0);
    static SEEN_SLOW_DIRECTION: AtomicU32 = AtomicU32::new(0);
    static SEEN_SLOW_CHARACTER: AtomicU32 = AtomicU32::new(0);
    static SEEN_SLOW_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_slow_lookup(
        locale: *mut u32,
        facet_id: *const u32,
        direction: u32,
        character: u32,
        descriptor: usize,
    ) -> u32 {
        SEEN_SLOW_LOCALE.store(locale as usize, Ordering::SeqCst);
        SEEN_SLOW_LOCALE_VALUE.store(unsafe { locale.read() }, Ordering::SeqCst);
        SEEN_SLOW_ID.store(facet_id as usize, Ordering::SeqCst);
        SEEN_SLOW_DIRECTION.store(direction, Ordering::SeqCst);
        SEEN_SLOW_CHARACTER.store(character, Ordering::SeqCst);
        SEEN_SLOW_DESCRIPTOR.store(descriptor, Ordering::SeqCst);
        SLOW_CALLS.fetch_add(1, Ordering::SeqCst);
        FALLBACK_FACET
    }

    unsafe extern "C" fn record_widen(facet: u32, character: u32) -> u8 {
        WIDEN_FACET.store(facet, Ordering::SeqCst);
        WIDEN_CHARACTER.store(character, Ordering::SeqCst);
        0x7e
    }

    unsafe extern "C" fn record_release(locale: *mut u32) {
        RELEASED_LOCALE.store(unsafe { locale.read() }, Ordering::SeqCst);
    }

    fn install_recording_ops() {
        unsafe {
            BASIC_IOS_INITIALIZE_OPS = BasicIosInitializeOps {
                slow_facet_lookup: record_slow_lookup,
                facet_widen: record_widen,
                locale_handle_release: record_release,
            };
            BASIC_IOS_FACET_ID = FACET_ID;
        }
        SLOW_CALLS.store(0, Ordering::SeqCst);
        WIDEN_FACET.store(0, Ordering::SeqCst);
        WIDEN_CHARACTER.store(0, Ordering::SeqCst);
        RELEASED_LOCALE.store(0, Ordering::SeqCst);
        SEEN_SLOW_LOCALE.store(0, Ordering::SeqCst);
        SEEN_SLOW_LOCALE_VALUE.store(0, Ordering::SeqCst);
        SEEN_SLOW_ID.store(0, Ordering::SeqCst);
        SEEN_SLOW_DIRECTION.store(0, Ordering::SeqCst);
        SEEN_SLOW_CHARACTER.store(0, Ordering::SeqCst);
        SEEN_SLOW_DESCRIPTOR.store(0, Ordering::SeqCst);
    }

    fn fixture() -> Option<(*mut BasicIosFields, *mut u32, *mut u32)> {
        let base = (*SLAB)? as *mut u8;
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            let stream = base.cast::<BasicIosFields>();
            let locale = base.add(LOCALE_OFFSET).cast::<u32>();
            let table = base.add(TABLE_OFFSET).cast::<u32>();
            (*stream).locale = locale as usize as u32;
            locale.add(2).write(table as usize as u32);
            Some((stream, locale, table))
        }
    }

    #[test]
    fn initializes_fields_and_uses_an_in_range_facet() {
        let _lock = BASIC_IOS_INITIALIZE_TEST_LOCK.lock();
        install_recording_ops();
        let Some((stream, locale, table)) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/basic_ios_initialize"));
            return;
        };
        unsafe {
            locale.add(3).write(FACET_ID + 1);
            locale.add(7).write(u32::MAX);
            table.add(FACET_ID as usize).write(DIRECT_FACET);
            basic_ios_initialize(stream.cast::<u8>(), 0);

            assert_eq!((*stream).flags, DEFAULT_FLAGS);
            assert_eq!((*stream).precision, DEFAULT_PRECISION);
            assert_eq!((*stream).width, 0);
            assert_eq!((*stream).state, 1);
            assert_eq!((*stream).exception_mask, 0);
            assert_eq!((*stream).streambuf, 0);
            assert_eq!((*stream).callback_state, 0);
            assert_eq!((*stream).fill_character, 0x7e);
            assert_eq!(locale.add(7).read(), 0);
        }
        assert_eq!(SLOW_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(WIDEN_FACET.load(Ordering::SeqCst), DIRECT_FACET);
        assert_eq!(WIDEN_CHARACTER.load(Ordering::SeqCst), SPACE_CHARACTER);
        assert_eq!(RELEASED_LOCALE.load(Ordering::SeqCst), locale as usize as u32);
    }

    #[test]
    fn falls_back_for_missing_facet_and_forwards_all_lookup_arguments() {
        let _lock = BASIC_IOS_INITIALIZE_TEST_LOCK.lock();
        install_recording_ops();
        let Some((stream, locale, _table)) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/basic_ios_initialize"));
            return;
        };
        unsafe {
            locale.add(3).write(FACET_ID);
            locale.add(7).write(41);
            basic_ios_initialize(stream.cast::<u8>(), 3);

            assert_eq!((*stream).state, 0);
            assert_eq!((*stream).streambuf, 3);
            assert_eq!((*stream).fill_character, 0x7e);
            assert_eq!(locale.add(7).read(), 42);
        }
        assert_eq!(SLOW_CALLS.load(Ordering::SeqCst), 1);
        assert_ne!(SEEN_SLOW_LOCALE.load(Ordering::SeqCst), stream as usize + 24);
        assert_eq!(SEEN_SLOW_LOCALE_VALUE.load(Ordering::SeqCst), locale as usize as u32);
        assert_eq!(SEEN_SLOW_ID.load(Ordering::SeqCst), ptr::addr_of!(BASIC_IOS_FACET_ID) as usize);
        assert_eq!(SEEN_SLOW_DIRECTION.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_SLOW_CHARACTER.load(Ordering::SeqCst), SPACE_CHARACTER);
        assert_eq!(SEEN_SLOW_DESCRIPTOR.load(Ordering::SeqCst), FALLBACK_FACET_DESCRIPTOR);
        assert_eq!(WIDEN_FACET.load(Ordering::SeqCst), FALLBACK_FACET);
        assert_eq!(RELEASED_LOCALE.load(Ordering::SeqCst), locale as usize as u32);
    }
}
