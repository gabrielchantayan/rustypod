//! Availability-gated resource cache getter.
//!
//! `resource_cache_get_if_available` is `FUN_082a6040` @ 0x082a6040. It
//! invokes vtable slot +0x0c; a zero result returns zero, otherwise it
//! tail-branches to [`super::cache::resource_cache_refresh_get`] for the
//! cache-object pointer at +0x04 with no forced refresh.

use super::cache::resource_cache_refresh_get;

/// Byte offset of the availability method inside the object's vtable.
const VTABLE_AVAILABLE_OFFSET: usize = 0x0c;

/// Byte offset of the cache-object pointer in the vtable-headed wrapper.
const CACHE_OBJECT_OFFSET: usize = 0x04;

/// Vtable slot +0x0c signature: returns nonzero when the cache is available.
type AvailableSlot = unsafe extern "C" fn(*mut u8) -> u32;

/// resource_cache_get_if_available — original: `FUN_082a6040` @ 0x082a6040
/// (52 bytes, exact: 0x082a6074 starts the next separately linked function's
/// `push {r4,lr}` prologue; **3 direct inbound `bl` call sites**, all plain
/// unconditional, zero predicated direct calls; the body has no direct `bl`,
/// one indirect `blx`, and one tail `b`, verified from `osos.dec`).
///
/// ```text
/// 082a6040  push    {r4,lr}
/// 082a6044  mov     r4,r0
/// 082a6048  ldr     r0,[r0]
/// 082a604c  ldr     r1,[r0,#0xc]
/// 082a6050  mov     r0,r4
/// 082a6054  blx     r1
/// 082a6058  cmp     r0,#0
/// 082a605c  ldrne  r0,[r4,#4]
/// 082a6060  popne  {r4,lr}
/// 082a6064  movne  r1,#0
/// 082a6068  bne    0x08047020
/// 082a606c  moveq  r0,#0
/// 082a6070  pop     {r4,pc}
/// ```
///
/// Calls the object's vtable slot +0x0c with the object. A zero result returns
/// zero without touching the cache-object pointer. Any nonzero result invokes
/// `resource_cache_refresh_get(cache_object, 0)`, returning its cached word.
/// The slot's concrete identity is not established, so this port preserves the
/// raw vtable dispatch rather than inventing a callee.
///
/// Deliberate deviation: Rust uses an ordinary call and return instead of the
/// ARM tail branch. Host fixtures store the +0x0c slot as a native-width
/// function pointer while object vtable links remain firmware `u32` words.
///
/// # Safety
///
/// `object` must be readable through its vtable word and vtable slot +0x0c.
/// When that slot returns nonzero, its +0x04 cache-object pointer must meet
/// [`resource_cache_refresh_get`]'s safety requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_cache_get_if_available(object: *mut u8) -> u32 {
    let vtable = object.cast::<u32>().read() as usize as *const u8;
    let available: AvailableSlot = vtable.add(VTABLE_AVAILABLE_OFFSET).cast::<AvailableSlot>().read();
    if available(object) == 0 {
        return 0;
    }
    let cache_object = object.add(CACHE_OBJECT_OFFSET).cast::<u32>().read() as usize as *mut u8;
    resource_cache_refresh_get(cache_object, 0)
}

/// resource_cache_auxiliary_get_if_available — `FUN_082a600c` @ 0x082a600c.
/// True extent: 52 bytes, ending at 0x082a603c; the next function starts
/// at 0x082a6040. Raw words verify two inbound plain BL calls
/// (0x08176fb4, 0x08177228), zero predicated BL calls, and a body with
/// zero direct BL, one indirect BLX, and one conditional tail B.
///
/// Calls virtual slot +0x0c. Zero returns zero without reading object+4.
/// Otherwise calls resident 0x08047060(cache_object, 0), which refreshes
/// a dirty resource cache and returns its auxiliary word at +0x61c.
/// Neither the virtual target nor the auxiliary word's meaning is invented.
///
/// Rust expresses the tail branch as a call/return; LLVM retains a tail BX
/// to 0x08047060 with a larger frame.
/// Host execution reuses the real sibling refresh port, then reads +0x61c;
/// this adds a discarded read of +0x620 but preserves refresh side effects.
/// Host vtable slots are native-width; object links remain target u32 words.
///
/// # Safety
/// Same object/vtable requirements as [`resource_cache_get_if_available`].
/// A successful gate requires a valid writable cache object through +0x620
/// and a valid resource callback tree when its dirty byte is nonzero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_cache_auxiliary_get_if_available(object: *mut u8) -> u32 {
    let vtable = object.cast::<u32>().read() as usize as *const u8;
    let available: AvailableSlot = vtable.add(VTABLE_AVAILABLE_OFFSET).cast::<AvailableSlot>().read();
    if available(object) == 0 {
        return 0;
    }
    let cache_object = object.add(CACHE_OBJECT_OFFSET).cast::<u32>().read() as usize as *mut u8;
    #[cfg(target_os = "none")]
    {
        let auxiliary_get: unsafe extern "C" fn(*mut u8, u32) -> u32 =
            core::mem::transmute(0x0804_7060usize);
        auxiliary_get(cache_object, 0)
    }
    #[cfg(not(target_os = "none"))]
    {
        resource_cache_refresh_get(cache_object, 0);
        cache_object.add(0x61c).cast::<u32>().read_volatile()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const CACHE_VALUE_OFFSET: usize = 0x620;
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut AVAILABLE_RESULT: u32 = 0;
    static mut AVAILABLE_OBJECT: *mut u8 = ptr::null_mut();
    static mut AVAILABLE_CALLS: u32 = 0;

    unsafe extern "C" fn available_stub(object: *mut u8) -> u32 {
        AVAILABLE_OBJECT = object;
        AVAILABLE_CALLS += 1;
        AVAILABLE_RESULT
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::RESOURCE_CACHE_GET_IF_AVAILABLE,
                0x1000,
            )
            .map(|pointer| pointer as usize)
        });
        SLAB.map(|pointer| pointer as *mut u8)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    unsafe fn prepare(available_result: u32, cache_value: u32) -> *mut u8 {
        let object = try_slab().expect("fixture slab checked by the caller's skip guard");
        let cache_object = object.add(0x100);
        let vtable = object.add(0x800);
        object.write_bytes(0, 8);
        cache_object.write_bytes(0, 0x700);
        AVAILABLE_RESULT = available_result;
        AVAILABLE_OBJECT = ptr::null_mut();
        AVAILABLE_CALLS = 0;
        write_word(object, 0, vtable as u32);
        write_word(object, CACHE_OBJECT_OFFSET, cache_object as u32);
        vtable
            .add(VTABLE_AVAILABLE_OFFSET)
            .cast::<AvailableSlot>()
            .write(available_stub);
        write_word(cache_object, CACHE_VALUE_OFFSET, cache_value);
        object
    }

    #[test]
    fn unavailable_object_returns_zero_without_reading_cache() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("app::resource::cache_available");
            return;
        }
        unsafe {
            let object = prepare(0, 0xfeed_face);
            write_word(object, CACHE_OBJECT_OFFSET, 1);
            assert_eq!(resource_cache_get_if_available(object), 0);
            assert_eq!(AVAILABLE_CALLS, 1);
            assert_eq!(AVAILABLE_OBJECT, object);
        }
    }

    #[test]
    fn available_object_returns_unforced_cached_value() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("app::resource::cache_available");
            return;
        }
        unsafe {
            let object = prepare(0x8000_0000, 0xa5c3_1e7f);
            assert_eq!(resource_cache_get_if_available(object), 0xa5c3_1e7f);
            assert_eq!(AVAILABLE_CALLS, 1);
            assert_eq!(AVAILABLE_OBJECT, object);
        }
    }

    #[test]
    fn auxiliary_unavailable_does_not_dereference_invalid_cache() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("app::resource::cache_available");
            return;
        }
        unsafe {
            let object = prepare(0, 0xfeed_face);
            write_word(object, CACHE_OBJECT_OFFSET, 1);
            assert_eq!(resource_cache_auxiliary_get_if_available(object), 0);
        }
    }

    #[test]
    fn auxiliary_nonzero_gate_returns_auxiliary_not_primary_cache_without_refresh() {
        let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("app::resource::cache_available");
            return;
        }
        unsafe {
            for gate in [1, 2, 0x8000_0000, u32::MAX] {
                let object = prepare(gate, 0xa5c3_1e7f);
                let cache = object.add(0x100);
                write_word(cache, 0x61c, 0x1234_abcd);
                assert_eq!(resource_cache_auxiliary_get_if_available(object), 0x1234_abcd);
                assert_eq!(cache.add(0x618).read(), 0);
                assert_eq!(cache.add(0x620).cast::<u32>().read(), 0xa5c3_1e7f);
            }
        }
    }
}
