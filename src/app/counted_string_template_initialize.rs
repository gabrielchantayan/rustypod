//! counted_string_template_initialize — original: `FUN_0805205c` @
//! 0x0805205c (52 bytes, including its two literal-pool words).
//!
//! Raw firmware establishes the true extent as 0x0805205c..0x08052090: ten
//! ARM instructions, two literal-pool words, then the next `push {lr}`
//! prologue. It has two unconditional outbound `bl` instructions (`strcpy`,
//! `strcat`), no predicated `bl`, and three unconditional inbound `bl` sites.
//! It clears the destination's u16 count and builds its trailing C string from
//! the two fixed-address byte sequences. Deliberate deviation: host builds
//! expose those otherwise fixed firmware addresses through a test seam.

use core::ptr::addr_of;

use crate::libc::{strcat::strcat, strcpy::strcpy};

type StringCopy = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;

// Volatile reads retain the retailOS call boundaries instead of inlining libc.
static STRING_COPY: StringCopy = strcpy;
static STRING_APPEND: StringCopy = strcat;

#[inline(always)]
fn string_copy() -> StringCopy {
    unsafe { core::ptr::read_volatile(addr_of!(STRING_COPY)) }
}

#[inline(always)]
fn string_append() -> StringCopy {
    unsafe { core::ptr::read_volatile(addr_of!(STRING_APPEND)) }
}

const TEMPLATE_PREFIX: *const u8 = 0x083e_25d0 as *const u8;
const TEMPLATE_SUFFIX: *const u8 = 0x083e_25c4 as *const u8;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct CountedStringTemplateInitializeOps {
    pub prefix: *const u8,
    pub suffix: *const u8,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_COUNTED_STRING_TEMPLATE_INITIALIZE_OPS: CountedStringTemplateInitializeOps =
    CountedStringTemplateInitializeOps { prefix: TEMPLATE_PREFIX, suffix: TEMPLATE_SUFFIX };

#[cfg(not(target_os = "none"))]
pub static mut COUNTED_STRING_TEMPLATE_INITIALIZE_OPS: CountedStringTemplateInitializeOps =
    DEFAULT_COUNTED_STRING_TEMPLATE_INITIALIZE_OPS;

#[inline(always)]
unsafe fn template_sources() -> (*const u8, *const u8) {
    #[cfg(target_os = "none")]
    {
        (TEMPLATE_PREFIX, TEMPLATE_SUFFIX)
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { core::ptr::read_volatile(addr_of!(COUNTED_STRING_TEMPLATE_INITIALIZE_OPS)) };
        (ops.prefix, ops.suffix)
    }
}

/// Clear the count at `destination` and copy the fixed template at offset two.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_string_template_initialize(destination: *mut u8) -> i32 {
    unsafe { destination.cast::<u16>().write(0) };
    let (prefix, suffix) = unsafe { template_sources() };
    unsafe { string_copy()(destination.add(2), prefix) };
    unsafe { string_append()(destination.add(2), suffix) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    struct SourcesRestore {
        prior: CountedStringTemplateInitializeOps,
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for SourcesRestore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(COUNTED_STRING_TEMPLATE_INITIALIZE_OPS).write(self.prior) };
        }
    }

    fn install_sources(prefix: *const u8, suffix: *const u8) -> SourcesRestore {
        let guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let prior = unsafe { addr_of!(COUNTED_STRING_TEMPLATE_INITIALIZE_OPS).read() };
        unsafe {
            addr_of_mut!(COUNTED_STRING_TEMPLATE_INITIALIZE_OPS)
                .write(CountedStringTemplateInitializeOps { prefix, suffix });
        }
        SourcesRestore { prior, _guard: guard }
    }

    #[test]
    fn initializes_raw_template_bytes_and_preserves_trailing_storage() {
        let prefix = [0x2a, 0];
        let suffix = [0x04, 0];
        let _sources = install_sources(prefix.as_ptr(), suffix.as_ptr());
        let mut destination = [0xcc; 8];

        assert_eq!(unsafe { counted_string_template_initialize(destination.as_mut_ptr()) }, 0);
        assert_eq!(destination, [0, 0, 0x2a, 0x04, 0, 0xcc, 0xcc, 0xcc]);
    }

    #[test]
    fn accepts_empty_prefix_and_suffix() {
        let prefix = [0];
        let suffix = [0];
        let _sources = install_sources(prefix.as_ptr(), suffix.as_ptr());
        let mut destination = [0xff; 5];

        unsafe { counted_string_template_initialize(destination.as_mut_ptr()) };
        assert_eq!(destination, [0, 0, 0, 0xff, 0xff]);
    }
}
