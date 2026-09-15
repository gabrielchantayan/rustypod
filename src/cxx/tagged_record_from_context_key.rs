//! `tagged_record_from_context_key` — original: `FUN_0813e6b0` @
//! `0x0813e6b0` (76 bytes).
//!
//! Raw ARM establishes the exact extent `0x0813e6b0..0x0813e6fc`: the next
//! separately linked function begins at `0x0813e700`; `0x0813e6fc` is a NOP
//! alignment word. The body contains three unconditional plain `bl` words
//! (`0x0813e6c4`, `0x0813e6d4`, and `0x0813e6e4`), with no predicated `bl`.
//!
//! # Algorithm
//!
//! Initialize `out` as a tagged record with zero payload and flag, call the
//! still-unported `FUN_08050418(context + 0x40, key)`, then reinitialize `out`
//! with that returned target-width word and the byte at `context + 0x44`.
//! `FUN_08050418` remains unnamed because its lookup semantics are not proved;
//! it is only identified here by its statically bound address and ABI.
//!
//! Deliberate deviations: the two retail calls to `FUN_0826fc2c` use the
//! canonical [`crate::cxx::tagged_record::tagged_record_init`] port. The
//! unported middle call uses its retail load address on target builds and a
//! recording boundary on host builds.

use crate::cxx::tagged_record::{tagged_record_init, TaggedRecord};

const CONTEXT_LOOKUP_OFFSET: usize = 0x40;
const CONTEXT_FLAG_OFFSET: usize = 0x44;
type RetailLookup = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_lookup(context: *mut u8, key: u32) -> u32 {
    let lookup: RetailLookup = unsafe { core::mem::transmute(0x0805_0418usize) };
    unsafe { lookup(context, key) }
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct LookupHostOps {
    lookup: RetailLookup,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_lookup(_context: *mut u8, _key: u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
const DEFAULT_LOOKUP_HOST_OPS: LookupHostOps = LookupHostOps {
    lookup: unavailable_lookup,
};

#[cfg(not(target_os = "none"))]
static mut LOOKUP_HOST_OPS: LookupHostOps = DEFAULT_LOOKUP_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_lookup(context: *mut u8, key: u32) -> u32 {
    unsafe { (LOOKUP_HOST_OPS.lookup)(context, key) }
}

/// Builds a tagged record from an opaque context and lookup key.
///
/// # Safety
///
/// `out` must be valid, four-byte aligned writable storage for a
/// [`TaggedRecord`]. `context` must be readable at offsets +0x40 through
/// +0x44. The original does not check either pointer or the lookup result.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_record_from_context_key")]
#[inline(never)]
pub unsafe extern "C" fn tagged_record_from_context_key(
    out: *mut TaggedRecord,
    context: *mut u8,
    key: u32,
) {
    unsafe {
        tagged_record_init(out, 0, 0);
        let payload = retail_lookup(context.add(CONTEXT_LOOKUP_OFFSET), key);
        let flag = context.add(CONTEXT_FLAG_OFFSET).read();
        tagged_record_init(out, payload, u32::from(flag));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut LAST_CALL: Option<(*mut u8, u32)> = None;
    static mut LOOKUP_RESULT: u32 = 0;

    unsafe extern "C" fn recording_lookup(context: *mut u8, key: u32) -> u32 {
        unsafe {
            LAST_CALL = Some((context, key));
            LOOKUP_RESULT
        }
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    struct Bench {
        _lock: TestLock,
    }

    fn bench(result: u32) -> Bench {
        let lock = lock_ops();
        unsafe {
            LAST_CALL = None;
            LOOKUP_RESULT = result;
            core::ptr::addr_of_mut!(LOOKUP_HOST_OPS).write_volatile(LookupHostOps {
                lookup: recording_lookup,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(LOOKUP_HOST_OPS).write_volatile(DEFAULT_LOOKUP_HOST_OPS);
            }
        }
    }

    #[repr(align(4))]
    struct ContextFixture {
        bytes: [u8; 0x48],
    }

    #[test]
    fn builds_tagged_record_from_lookup_result_and_low_flag_byte() {
        let mut context = ContextFixture { bytes: [0xa5; 0x48] };
        context.bytes[CONTEXT_FLAG_OFFSET] = 0xe7;
        let mut out = TaggedRecord { descriptor: 0, payload: 0, flag: 0 };
        let _bench = bench(0x1234_5678);

        unsafe {
            tagged_record_from_context_key(&mut out, context.bytes.as_mut_ptr(), 0xdead_beef);
        }

        assert_eq!(unsafe { LAST_CALL }, Some((unsafe { context.bytes.as_mut_ptr().add(0x40) }, 0xdead_beef)));
        assert_eq!(out.descriptor, crate::cxx::tagged_record::TAGGED_RECORD_DESCRIPTOR);
        assert_eq!(out.payload, 0x1234_5678);
        assert_eq!(out.flag, 0xe7);
    }

    #[test]
    fn preserves_zero_lookup_result_and_context_bytes() {
        let mut context = ContextFixture { bytes: [0x5a; 0x48] };
        context.bytes[CONTEXT_FLAG_OFFSET] = 0;
        let before = context.bytes;
        let mut out = TaggedRecord { descriptor: 0xffff_ffff, payload: 1, flag: 2 };
        let _bench = bench(0);

        unsafe {
            tagged_record_from_context_key(&mut out, context.bytes.as_mut_ptr(), 7);
        }

        assert_eq!(out.payload, 0);
        assert_eq!(out.flag, 0);
        assert_eq!(context.bytes, before);
    }
}
