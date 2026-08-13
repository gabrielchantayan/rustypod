//! Byte-block checksum forwarder — `FUN_0802c03c` @ 0x0802c03c (28 bytes).
//!
//! Reference: `decomp/c/001/0802c03c_FUN_0802c03c.c`; raw ARM loads inherited
//! parser state into r0-r2, calls 0x0802b6a8, discards its status, and returns.
//! The Ghidra entry has no explicit parameters: this is a continuation-style
//! forwarding edge whose live parser state belongs to its surrounding caller.
//! The Rust port consequently preserves the no-argument, void ABI and makes
//! the unported ROM target a direct target call. Host tests replace that edge
//! with a recorder; no behavior of the checksum reader itself is reproduced.

/// Unported byte-block copy/checksum reader reached by the original call.
const ROM_BYTE_BLOCK_CHECKSUM_READER: usize = 0x0802_b6a8;

/// ABI of the original no-explicit-argument continuation edge.
#[cfg(test)]
pub type ByteBlockChecksumReaderFn = unsafe extern "C" fn();

/// Host-only integration seam for the unported reader.
#[cfg(test)]
#[derive(Clone, Copy)]
pub struct ByteBlockChecksumForwardOps {
    pub invoke_reader: ByteBlockChecksumReaderFn,
}

#[cfg(test)]
unsafe extern "C" fn unavailable_byte_block_checksum_reader() {
    unreachable!("host tests must install a byte-block checksum reader");
}

/// Host tests replace the direct-ROM reader with a recording callback.
#[cfg(test)]
pub static mut BYTE_BLOCK_CHECKSUM_FORWARD_OPS: ByteBlockChecksumForwardOps =
    ByteBlockChecksumForwardOps {
        invoke_reader: unavailable_byte_block_checksum_reader,
    };

#[cfg(test)]
#[inline(always)]
unsafe fn byte_block_checksum_forward_ops() -> ByteBlockChecksumForwardOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BYTE_BLOCK_CHECKSUM_FORWARD_OPS))
}

/// forward_byte_block_checksum_reader — original: `FUN_0802c03c` @
/// 0x0802c03c (28 bytes). Reference:
/// `decomp/c/001/0802c03c_FUN_0802c03c.c`.
///
/// Invokes the byte-block copy/checksum reader at 0x0802b6a8 with the original
/// continuation's no-explicit-argument ABI, ignores the reader's status, and
/// returns to its caller. On target this is a direct ROM call. The host-only
/// callback seam exists solely to observe the invocation without branching to
/// unmapped firmware.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn forward_byte_block_checksum_reader() {
    let reader: unsafe extern "C" fn() = core::mem::transmute(ROM_BYTE_BLOCK_CHECKSUM_READER);
    reader();
}

/// Host-test counterpart of [`forward_byte_block_checksum_reader`].
#[cfg(test)]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn forward_byte_block_checksum_reader() {
    (byte_block_checksum_forward_ops().invoke_reader)();
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut INVOCATIONS: usize = 0;

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved: ByteBlockChecksumForwardOps,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe { BYTE_BLOCK_CHECKSUM_FORWARD_OPS = self.saved };
        }
    }

    fn install_recording_reader() -> TestOps {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved =
                core::ptr::read_volatile(core::ptr::addr_of!(BYTE_BLOCK_CHECKSUM_FORWARD_OPS));
            BYTE_BLOCK_CHECKSUM_FORWARD_OPS = ByteBlockChecksumForwardOps {
                invoke_reader: record_reader,
            };
            core::ptr::addr_of_mut!(INVOCATIONS).write(0);
            TestOps { _lock: lock, saved }
        }
    }

    unsafe extern "C" fn record_reader() {
        let invocations = core::ptr::addr_of!(INVOCATIONS).read();
        core::ptr::addr_of_mut!(INVOCATIONS).write(invocations + 1);
    }

    #[test]
    fn invokes_the_reader_once_and_returns_to_its_caller() {
        let _ops = install_recording_reader();

        unsafe { forward_byte_block_checksum_reader() };

        assert_eq!(unsafe { INVOCATIONS }, 1, "exactly one ROM-reader call");
    }
}
