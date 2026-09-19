//! Scoped-context 'tdat' message dispatch.

use crate::libc::bzero::bzero;
use super::scoped_context::scoped_context_owner_validity;
use crate::ui::tdat_message_dispatch::tdat_dispatch_message;

/// Message word loaded from the original's literal pool at `0x080617b8`.
const TDAT_MESSAGE: u32 = 0x7464_706c;
/// Returned when the owner is invalid or does not acknowledge the dispatch.
const TDAT_DISPATCH_REJECTED: u32 = 0xffff_ffce;
/// Owner byte which must equal one after dispatch (`ldrb r1,[r4,#0x16]`).
const OWNER_DISPATCH_ACK_OFFSET: usize = 0x16;

/// scoped_context_owner_dispatch_tdat_message — original: `FUN_08061768` @
/// `0x08061768` (80 instruction bytes plus the 4-byte literal pool word at
/// `0x080617b8`; next function boundary `0x080617bc`).
///
/// Raw ARM has 4 direct plain `bl` callers and no predicated `bl` callers.
/// Its body has three unconditional `bl` instructions: owner validation,
/// zeroing the 16-byte argument record, and 'tdat' message dispatch.
///
/// Algorithm: validate that `owner` begins with a 'tdat' element pointer,
/// zero a four-word argument record, then set its first two target words to
/// `owner` and `value`. Dispatch message `0x7464706c` to the element. Return
/// the dispatch result only if owner byte +0x16 equals one; otherwise return
/// `0xffffffce`.
///
/// Deliberate deviation: calls the already-ported owner predicate, bzero, and
/// dispatcher directly rather than their stock addresses. The temporary uses
/// `u32` words to retain the target's 4-byte pointer field layout on hosts.
///
/// # Safety
///
/// `owner` may be NULL. A non-NULL owner must begin with a readable native
/// pointer to a readable 'tdat' element and be readable through byte +0x16.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.scoped_context_owner_dispatch_tdat_message")]
pub unsafe extern "C" fn scoped_context_owner_dispatch_tdat_message(
    owner: *mut u8,
    value: u32,
) -> u32 {
    if scoped_context_owner_validity(owner.cast()) == 0 {
        return TDAT_DISPATCH_REJECTED;
    }

    let mut arguments = [0u32; 4];
    bzero(arguments.as_mut_ptr().cast(), 16);
    arguments[0] = owner as usize as u32;
    arguments[1] = value;

    let element = owner.cast::<*mut u8>().read();
    let result = tdat_dispatch_message(element, TDAT_MESSAGE, arguments.as_mut_ptr().cast());
    if owner.add(OWNER_DISPATCH_ACK_OFFSET).read() == 1 {
        result
    } else {
        TDAT_DISPATCH_REJECTED
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::ui::tdat_message_dispatch::{TdatMessageDispatch, TdatMessageOps, TDAT_MESSAGE_OPS};
    use std::sync::Mutex;

    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const OTHER_CLASS_TAG: u32 = 0x706c_7374;
    const MESSAGE_HANDLER_WORD: usize = 0x4c / 4;
    const MESSAGE_CONTEXT_WORD: usize = 0x50 / 4;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: u32 = 0;
    static mut DISPATCH_ELEMENT: usize = 0;
    static mut DISPATCH_MESSAGE: u32 = 0;
    static mut DISPATCH_ARGUMENTS: [u32; 4] = [0; 4];
    static mut DISPATCH_RESULT: u32 = 0;

    unsafe extern "C" fn record_dispatch(
        _handler_address: u32,
        element: *mut u8,
        message: u32,
        arguments: *mut u8,
        _context: u32,
    ) -> u32 {
        DISPATCH_CALLS += 1;
        DISPATCH_ELEMENT = element as usize;
        DISPATCH_MESSAGE = message;
        DISPATCH_ARGUMENTS = arguments.cast::<[u32; 4]>().read();
        DISPATCH_RESULT
    }

    struct OpsGuard(TdatMessageOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { TDAT_MESSAGE_OPS = self.0 };
        }
    }

    unsafe fn install_recorder(result: u32) -> OpsGuard {
        let previous = TDAT_MESSAGE_OPS;
        TDAT_MESSAGE_OPS = TdatMessageOps {
            dispatch: record_dispatch as TdatMessageDispatch,
        };
        DISPATCH_CALLS = 0;
        DISPATCH_ELEMENT = 0;
        DISPATCH_MESSAGE = 0;
        DISPATCH_ARGUMENTS = [!0; 4];
        DISPATCH_RESULT = result;
        OpsGuard(previous)
    }

    #[repr(C)]
    struct Owner {
        element: *mut u8,
        padding: [u8; OWNER_DISPATCH_ACK_OFFSET - core::mem::size_of::<*mut u8>()],
        dispatch_ack: u8,
    }

    fn tdat_element(tag: u32) -> [u32; MESSAGE_CONTEXT_WORD + 1] {
        let mut element = [0u32; MESSAGE_CONTEXT_WORD + 1];
        element[1] = tag;
        element[MESSAGE_HANDLER_WORD] = 0x0812_3456;
        element[MESSAGE_CONTEXT_WORD] = 0x9abc_def0;
        element
    }

    #[test]
    fn invalid_owners_are_rejected_without_dispatch() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder(0xc0de_cafe) };
        let mut other = tdat_element(OTHER_CLASS_TAG);
        let mut owner = Owner {
            element: other.as_mut_ptr().cast(),
            padding: [0; OWNER_DISPATCH_ACK_OFFSET - core::mem::size_of::<*mut u8>()],
            dispatch_ack: 1,
        };

        assert_eq!(unsafe { scoped_context_owner_dispatch_tdat_message(core::ptr::addr_of_mut!(owner).cast(), 7) }, TDAT_DISPATCH_REJECTED);
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
    }

    #[test]
    fn acknowledged_tdat_owner_forwards_zero_padded_record() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder(0xc0de_cafe) };
        let mut element = tdat_element(TDAT_CLASS_TAG);
        let mut owner = Owner {
            element: element.as_mut_ptr().cast(),
            padding: [0; OWNER_DISPATCH_ACK_OFFSET - core::mem::size_of::<*mut u8>()],
            dispatch_ack: 1,
        };

        assert_eq!(unsafe { scoped_context_owner_dispatch_tdat_message(core::ptr::addr_of_mut!(owner).cast(), 0x1234_5678) }, 0xc0de_cafe);
        unsafe {
            assert_eq!(DISPATCH_CALLS, 1);
            assert_eq!(DISPATCH_ELEMENT, element.as_mut_ptr() as usize);
            assert_eq!(DISPATCH_MESSAGE, TDAT_MESSAGE);
            assert_eq!(DISPATCH_ARGUMENTS, [(&mut owner as *mut Owner) as usize as u32, 0x1234_5678, 0, 0]);
        }
    }

    #[test]
    fn unacknowledged_owner_discards_dispatch_result() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder(0xc0de_cafe) };
        let mut element = tdat_element(TDAT_CLASS_TAG);
        let mut owner = Owner {
            element: element.as_mut_ptr().cast(),
            padding: [0; OWNER_DISPATCH_ACK_OFFSET - core::mem::size_of::<*mut u8>()],
            dispatch_ack: 0,
        };

        assert_eq!(unsafe { scoped_context_owner_dispatch_tdat_message(core::ptr::addr_of_mut!(owner).cast(), 0) }, TDAT_DISPATCH_REJECTED);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
    }
}
