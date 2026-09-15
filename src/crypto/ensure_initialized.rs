//! One-time initialization gate for the retailOS OpenSSL subsystem.
//!
//! `crypto_ensure_initialized` — original: `FUN_080ebcb4` @ 0x080ebcb4
//! (44 bytes: 36 bytes of code plus the literal-pool word at 0x080ebcdc;
//! Ghidra's reported 64-byte extent absorbs the next function, which starts
//! at 0x080ebce0). Raw decoding finds five unconditional `bl` callers and no
//! predicated `bl` callers. The body itself has one unconditional `bl`, to
//! `FUN_0805f430` @ 0x0805f430, and no predicated call.
//!
//! The gate tests the word at 0x080a96c0, the +4 initialized field of the
//! object pointer stored in its literal pool. On a cold gate it sets that word
//! before invoking OpenSSL's registration initializer, then tail-branches to
//! the six-instruction helper at 0x08049a10 which sets the independent word
//! at 0x08049a28 if it is clear. A warm gate does neither operation.
//!
//! Deliberate deviation: the stock tail branch is a normal Rust call sequence;
//! its observable writes and callee ordering are unchanged. `FUN_0805f430`
//! has not yet been ported, so target builds call its fixed retailOS address;
//! host builds expose that one call as a test seam.

const CRYPTO_INITIALIZED_SLOT: *mut u32 = 0x080a_96c0 as *mut u32;
const SECONDARY_INITIALIZED_SLOT: *mut u32 = 0x0804_9a28 as *mut u32;
const RETAIL_CRYPTO_INITIALIZE: usize = 0x0805_f430;

type CryptoInitialize = unsafe extern "C" fn() -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_crypto() {
    let initialize: CryptoInitialize = unsafe { core::mem::transmute(RETAIL_CRYPTO_INITIALIZE) };
    unsafe { initialize(); }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_initialize_crypto() -> u32 {
    0
}

/// Host seam for the unported OpenSSL registration initializer.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct CryptoEnsureInitializedOps {
    pub initialize_crypto: CryptoInitialize,
}

/// Active host seam for `FUN_0805f430`; target builds always call retailOS.
#[cfg(not(target_os = "none"))]
pub static mut CRYPTO_ENSURE_INITIALIZED_OPS: CryptoEnsureInitializedOps = CryptoEnsureInitializedOps {
    initialize_crypto: host_initialize_crypto,
};

#[cfg(not(target_os = "none"))]
static mut HOST_CRYPTO_INITIALIZED: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut HOST_SECONDARY_INITIALIZED: u32 = 0;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn initialize_crypto() {
    unsafe { (CRYPTO_ENSURE_INITIALIZED_OPS.initialize_crypto)(); }
}

/// Ensure that the OpenSSL registration path has run once.
///
/// # Safety
///
/// On target, the retailOS global slots at 0x080a96c0 and 0x08049a28 must be
/// writable. Host callers that replace [`CRYPTO_ENSURE_INITIALIZED_OPS`] must
/// synchronize access to that mutable test seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn crypto_ensure_initialized() {
    #[cfg(target_os = "none")]
    let initialized = unsafe { CRYPTO_INITIALIZED_SLOT.read_volatile() };
    #[cfg(not(target_os = "none"))]
    let initialized = unsafe { HOST_CRYPTO_INITIALIZED };
    if initialized != 0 {
        return;
    }

    #[cfg(target_os = "none")]
    unsafe { CRYPTO_INITIALIZED_SLOT.write_volatile(1); }
    #[cfg(not(target_os = "none"))]
    unsafe { HOST_CRYPTO_INITIALIZED = 1; }

    unsafe { initialize_crypto(); }

    #[cfg(target_os = "none")]
    let secondary_initialized = unsafe { SECONDARY_INITIALIZED_SLOT.read_volatile() };
    #[cfg(not(target_os = "none"))]
    let secondary_initialized = unsafe { HOST_SECONDARY_INITIALIZED };
    if secondary_initialized == 0 {
        #[cfg(target_os = "none")]
        unsafe { SECONDARY_INITIALIZED_SLOT.write_volatile(1); }
        #[cfg(not(target_os = "none"))]
        unsafe { HOST_SECONDARY_INITIALIZED = 1; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INITIALIZE_CALLS: u32 = 0;

    unsafe extern "C" fn record_initialize() -> u32 {
        unsafe { INITIALIZE_CALLS += 1; }
        0
    }

    struct FixtureReset(CryptoEnsureInitializedOps);

    impl Drop for FixtureReset {
        fn drop(&mut self) {
            unsafe {
                CRYPTO_ENSURE_INITIALIZED_OPS = self.0;
                HOST_CRYPTO_INITIALIZED = 0;
                HOST_SECONDARY_INITIALIZED = 0;
                INITIALIZE_CALLS = 0;
            }
        }
    }

    #[test]
    fn cold_gate_initializes_both_flags_and_calls_registration_once() {
        let _lock = TEST_LOCK.lock();
        let reset = unsafe {
            let old = CRYPTO_ENSURE_INITIALIZED_OPS;
            CRYPTO_ENSURE_INITIALIZED_OPS = CryptoEnsureInitializedOps { initialize_crypto: record_initialize };
            HOST_CRYPTO_INITIALIZED = 0;
            HOST_SECONDARY_INITIALIZED = 0;
            INITIALIZE_CALLS = 0;
            FixtureReset(old)
        };

        unsafe { crypto_ensure_initialized(); }

        unsafe {
            assert_eq!(HOST_CRYPTO_INITIALIZED, 1);
            assert_eq!(HOST_SECONDARY_INITIALIZED, 1);
            assert_eq!(INITIALIZE_CALLS, 1);
        }
        drop(reset);
    }

    #[test]
    fn warm_gate_skips_registration_and_secondary_flag() {
        let _lock = TEST_LOCK.lock();
        let reset = unsafe {
            let old = CRYPTO_ENSURE_INITIALIZED_OPS;
            CRYPTO_ENSURE_INITIALIZED_OPS = CryptoEnsureInitializedOps { initialize_crypto: record_initialize };
            HOST_CRYPTO_INITIALIZED = 1;
            HOST_SECONDARY_INITIALIZED = 0;
            INITIALIZE_CALLS = 0;
            FixtureReset(old)
        };

        unsafe { crypto_ensure_initialized(); }

        unsafe {
            assert_eq!(HOST_SECONDARY_INITIALIZED, 0);
            assert_eq!(INITIALIZE_CALLS, 0);
        }
        drop(reset);
    }
}
