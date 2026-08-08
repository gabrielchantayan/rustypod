//! App string resolution from provider-tagged tables.

use core::mem::MaybeUninit;

const RESOLVER_PRIMARY_SOURCE: usize = 0x04;
const RESOLVER_PARENT_SOURCE: usize = 0x18;

/// The two-word lookup result consumed by the resolver.
///
/// Both fields are 32-bit firmware addresses: the first is copied to the
/// caller's output slot and the second is returned.  The resolver only borrows
/// these values; the ARM body contains no allocation, retain, or release.
#[repr(C)]
pub struct AppStringResolveRecord {
    pub output: u32,
    pub value: u32,
}

/// Resolves a record from a provider source (the behavior at `0x0812d20c`).
///
/// A nonzero result means `record_slot` now names a valid
/// [`AppStringResolveRecord`].
pub type AppStringResolveLookup = unsafe extern "C" fn(
    source: u32,
    context: *mut u8,
    value: *mut u8,
    record_slot: *mut *mut AppStringResolveRecord,
) -> i32;

/// Searches the tagged resolver's primary fallback source (at `0x0815bcd4`).
pub type AppStringResolveFallback = unsafe extern "C" fn(
    source: u32,
    context: *mut u8,
    value: *mut u8,
    output_slot: *mut *mut u8,
) -> *mut u8;

/// Unported provider-table operations used by [`app_string_resolver_resolve`].
///
/// The tagged resolver itself is ported here; its provider lookup and range
/// table formats remain opaque and are delegated at their original call
/// boundaries.
#[derive(Clone, Copy)]
pub struct AppStringResolveOps {
    pub lookup: AppStringResolveLookup,
    pub fallback: AppStringResolveFallback,
}

unsafe extern "C" fn missing_app_string_resolve_lookup(
    _source: u32,
    _context: *mut u8,
    _value: *mut u8,
    _record_slot: *mut *mut AppStringResolveRecord,
) -> i32 {
    panic!("app_string_resolver_resolve requires provider lookup 0x0812d20c")
}

unsafe extern "C" fn missing_app_string_resolve_fallback(
    _source: u32,
    _context: *mut u8,
    _value: *mut u8,
    _output_slot: *mut *mut u8,
) -> *mut u8 {
    panic!("app_string_resolver_resolve requires fallback lookup 0x0815bcd4")
}

/// Active provider-table operations. Target integration replaces these before
/// routing retailOS through this resolver.
pub static mut APP_STRING_RESOLVE_OPS: AppStringResolveOps = AppStringResolveOps {
    lookup: missing_app_string_resolve_lookup,
    fallback: missing_app_string_resolve_fallback,
};

#[inline(always)]
unsafe fn app_string_resolve_ops() -> AppStringResolveOps {
    core::ptr::read_volatile(core::ptr::addr_of!(APP_STRING_RESOLVE_OPS))
}

/// Reads a 32-bit word from a word-aligned foreign firmware object.
#[inline(always)]
unsafe fn resolver_word(resolver: *const u8, offset: usize) -> u32 {
    resolver.add(offset).cast::<u32>().read()
}

/// Copies a successful provider record to the resolver ABI's two outputs.
#[inline(always)]
unsafe fn return_record(
    record: *mut AppStringResolveRecord,
    output_slot: *mut *mut u8,
) -> *mut u8 {
    output_slot.write((*record).output as usize as *mut u8);
    (*record).value as usize as *mut u8
}

/// app_string_resolver_resolve — original: `FUN_0811ca58` @ 0x0811ca58
/// (172 bytes).
///
/// Resolves `value` through a provider-tagged resolver object.  Tag 1 looks up
/// the primary source at +0x04; tag 2 first tries the optional parent source
/// at +0x18 and otherwise delegates to its primary range-table fallback.  A
/// successful provider lookup copies the record's word 0 to `output_slot` and
/// returns word 1.  A failed tag-1 lookup clears `output_slot`; an unknown tag
/// returns NULL without touching it.  Tag-2 fallback output and return values
/// are passed through unchanged.
///
/// # Safety
/// `resolver` must designate a live, word-aligned firmware object with a tag
/// byte at +0x00 and 32-bit source words at +0x04/+0x18. `output_slot` must be
/// writable. Installed operations must uphold their ABI: a nonzero `lookup`
/// result must initialize its record slot with a valid two-word record.
///
/// Sources: raw ARM at `decomp/osos.asm` 0x0811ca58; reference C at
/// `decomp/c/010/0811ca58_FUN_0811ca58.c`; provider lookup 0x0812d20c and
/// fallback 0x0815bcd4.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_string_resolver_resolve(
    resolver: *mut u8,
    context: *mut u8,
    value: *mut u8,
    output_slot: *mut *mut u8,
) -> *mut u8 {
    let ops = app_string_resolve_ops();
    match resolver.read() {
        1 => {
            let mut record = MaybeUninit::<*mut AppStringResolveRecord>::uninit();
            if (ops.lookup)(
                resolver_word(resolver, RESOLVER_PRIMARY_SOURCE),
                context,
                value,
                record.as_mut_ptr(),
            ) == 0
            {
                output_slot.write(core::ptr::null_mut());
                return core::ptr::null_mut();
            }
            return_record(record.assume_init(), output_slot)
        }
        2 => {
            let parent_source = resolver_word(resolver, RESOLVER_PARENT_SOURCE);
            if parent_source != 0 {
                let mut record = MaybeUninit::<*mut AppStringResolveRecord>::uninit();
                if (ops.lookup)(parent_source, context, value, record.as_mut_ptr()) != 0 {
                    return return_record(record.assume_init(), output_slot);
                }
            }
            (ops.fallback)(
                resolver_word(resolver, RESOLVER_PRIMARY_SOURCE),
                context,
                value,
                output_slot,
            )
        }
        _ => core::ptr::null_mut(),
    }
}

/// app_string_resolve — original: `FUN_0811ca48` @ 0x0811ca48 (16 bytes).
///
/// The adapter preserves its three incoming arguments, provides the one-word
/// stack output slot required by [`app_string_resolver_resolve`], and returns
/// the resolver's `r0` unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_string_resolve(
    resolver: *mut u8,
    context: *mut u8,
    value: *mut u8,
) -> *mut u8 {
    let mut output_slot = MaybeUninit::<*mut u8>::uninit();
    app_string_resolver_resolve(resolver, context, value, output_slot.as_mut_ptr())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP_CALLS: u32 = 0;
    static mut FALLBACK_CALLS: u32 = 0;
    static mut LAST_LOOKUP_SOURCE: u32 = 0;
    static mut LAST_FALLBACK_SOURCE: u32 = 0;
    static mut LOOKUP_RECORD: *mut AppStringResolveRecord = core::ptr::null_mut();
    static mut FALLBACK_RESULT: *mut u8 = core::ptr::null_mut();
    static mut FALLBACK_OUTPUT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn mock_lookup(
        source: u32,
        _context: *mut u8,
        _value: *mut u8,
        record_slot: *mut *mut AppStringResolveRecord,
    ) -> i32 {
        LOOKUP_CALLS += 1;
        LAST_LOOKUP_SOURCE = source;
        if LOOKUP_RECORD.is_null() {
            0
        } else {
            record_slot.write(LOOKUP_RECORD);
            1
        }
    }

    unsafe extern "C" fn mock_fallback(
        source: u32,
        _context: *mut u8,
        _value: *mut u8,
        output_slot: *mut *mut u8,
    ) -> *mut u8 {
        FALLBACK_CALLS += 1;
        LAST_FALLBACK_SOURCE = source;
        output_slot.write(FALLBACK_OUTPUT);
        FALLBACK_RESULT
    }

    struct RestoreOps;

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe {
                APP_STRING_RESOLVE_OPS = AppStringResolveOps {
                    lookup: missing_app_string_resolve_lookup,
                    fallback: missing_app_string_resolve_fallback,
                };
            }
        }
    }

    fn mock_ops() -> (MutexGuard<'static, ()>, RestoreOps) {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            LOOKUP_CALLS = 0;
            FALLBACK_CALLS = 0;
            LAST_LOOKUP_SOURCE = 0;
            LAST_FALLBACK_SOURCE = 0;
            LOOKUP_RECORD = core::ptr::null_mut();
            FALLBACK_RESULT = core::ptr::null_mut();
            FALLBACK_OUTPUT = core::ptr::null_mut();
            APP_STRING_RESOLVE_OPS = AppStringResolveOps {
                lookup: mock_lookup,
                fallback: mock_fallback,
            };
        }
        (lock, RestoreOps)
    }

    fn resolver(tag: u32, primary_source: u32, parent_source: u32) -> [u32; 7] {
        [tag, primary_source, 0, 0, 0, 0, parent_source]
    }

    #[test]
    fn primary_lookup_copies_the_record_output_and_returns_its_value() {
        let (_lock, _restore) = mock_ops();
        let mut fixture = resolver(1, 0x1020_3040, 0);
        let mut record = AppStringResolveRecord {
            output: 0x1122_3344,
            value: 0x5566_7788,
        };
        let mut output = core::ptr::null_mut();

        unsafe {
            LOOKUP_RECORD = &mut record;
            assert_eq!(
                app_string_resolver_resolve(
                    fixture.as_mut_ptr().cast(),
                    0x100usize as *mut u8,
                    0x200usize as *mut u8,
                    &mut output,
                ),
                0x5566_7788usize as *mut u8,
            );
            assert_eq!(output, 0x1122_3344usize as *mut u8);
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(LAST_LOOKUP_SOURCE, 0x1020_3040);
            assert_eq!(FALLBACK_CALLS, 0);
        }
    }

    #[test]
    fn failed_primary_lookup_clears_output_and_returns_null() {
        let (_lock, _restore) = mock_ops();
        let mut fixture = resolver(1, 0x1020_3040, 0);
        let mut output = 0xaaaa_bbbbusize as *mut u8;

        unsafe {
            assert!(app_string_resolver_resolve(
                fixture.as_mut_ptr().cast(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut output,
            )
            .is_null());
            assert!(output.is_null());
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(FALLBACK_CALLS, 0);
        }
    }

    #[test]
    fn tagged_parent_success_precedes_the_fallback() {
        let (_lock, _restore) = mock_ops();
        let mut fixture = resolver(2, 0x1020_3040, 0x5060_7080);
        let mut record = AppStringResolveRecord {
            output: 0x1122_3344,
            value: 0x5566_7788,
        };
        let mut output = core::ptr::null_mut();

        unsafe {
            LOOKUP_RECORD = &mut record;
            assert_eq!(
                app_string_resolver_resolve(
                    fixture.as_mut_ptr().cast(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut output,
                ),
                0x5566_7788usize as *mut u8,
            );
            assert_eq!(output, 0x1122_3344usize as *mut u8);
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(LAST_LOOKUP_SOURCE, 0x5060_7080);
            assert_eq!(FALLBACK_CALLS, 0);
        }
    }

    #[test]
    fn absent_or_failed_parent_delegates_fallback_output_and_return_unchanged() {
        let (_lock, _restore) = mock_ops();
        let mut fixture = resolver(2, 0x1020_3040, 0);
        let mut output = core::ptr::null_mut();

        unsafe {
            FALLBACK_OUTPUT = 0x1122_3344usize as *mut u8;
            FALLBACK_RESULT = 0x5566_7788usize as *mut u8;
            assert_eq!(
                app_string_resolver_resolve(
                    fixture.as_mut_ptr().cast(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut output,
                ),
                FALLBACK_RESULT,
            );
            assert_eq!(output, FALLBACK_OUTPUT);
            assert_eq!(LOOKUP_CALLS, 0);
            assert_eq!(FALLBACK_CALLS, 1);
            assert_eq!(LAST_FALLBACK_SOURCE, 0x1020_3040);
        }
    }

    #[test]
    fn unknown_tag_returns_null_without_changing_the_output_slot() {
        let (_lock, _restore) = mock_ops();
        let mut fixture = resolver(3, 0x1020_3040, 0x5060_7080);
        let original_output = 0xaaaa_bbbbusize as *mut u8;
        let mut output = original_output;

        unsafe {
            assert!(app_string_resolver_resolve(
                fixture.as_mut_ptr().cast(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut output,
            )
            .is_null());
            assert_eq!(output, original_output);
            assert_eq!(LOOKUP_CALLS, 0);
            assert_eq!(FALLBACK_CALLS, 0);
        }
    }
}
