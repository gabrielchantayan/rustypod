//! Validated length-prefixed request dispatch.
//!
//! `FUN_08048258` at `0x08048258` is a 112-byte ARM body ending at
//! `0x080482c4`; the independently linked successor starts at `0x080482c8`.
//! Decoding every aligned immediate ARM B/BL word in `osos.dec` finds six
//! inbound call sites, all unconditional `bl`: `0x08048424`, `0x08048458`,
//! `0x0805d7e0`, `0x0805d91c`, `0x0805d960`, and `0x0805d974`. There are no
//! predicated or direct-tail branch callers.
//!
//! The owner slot supplies an opaque context whose `+0x30` bit 1 selects a
//! byte- or little-endian-u16 length prefix. Lengths through five are accepted
//! directly; larger values must not exceed the context's `+0x1e` u16 limit,
//! otherwise the function returns `0x030e` without constructing or dispatching
//! a request. A valid input is copied, prefix included, into request storage at
//! `+0x1c`; request word `+0x04` is zeroed; then the unrecovered callee at
//! `0x08041038` receives the owner and request. Its low 16-bit status is
//! sign-extended exactly as the final `lsl #16; asr #16` pair does.
//!
//! Deliberate deviation: the unrecovered callee is a read-volatile dispatch
//! seam. Device builds call its verified fixed address; host tests install a
//! recorder. The target context has only word-aligned scalar fields here, so
//! the `#[repr(C)]` byte layout preserves its recovered offsets on every host.

use core::{mem::MaybeUninit, ptr};

const LENGTH_LIMIT_OFFSET: usize = 0x1e;
const FLAGS_OFFSET: usize = 0x30;
const WIDE_LENGTH_FLAG: u32 = 2;
const REQUEST_WORD_OFFSET: usize = 4;
const REQUEST_PAYLOAD_OFFSET: usize = 0x1c;
const REQUEST_STORAGE_SIZE: usize = 0x228;
const LENGTH_OUT_OF_RANGE: i32 = 0x030e;
const FIRMWARE_REQUEST_DISPATCH_ADDRESS: usize = 0x0804_1038;

/// Opaque owner whose first target word points at the validation context.
#[repr(C)]
pub struct LengthPrefixedRequestOwner {
    /// `+0x00`: context used for prefix width and length validation.
    pub context: *mut LengthPrefixedRequestContext,
}

/// Prefix of the opaque validation context recovered by this wrapper.
#[repr(C)]
pub struct LengthPrefixedRequestContext {
    /// `+0x00..+0x1d`: not recovered here.
    pub opaque_00: [u8; LENGTH_LIMIT_OFFSET],
    /// `+0x1e`: largest accepted length when the prefix is greater than five.
    pub length_limit: u16,
    /// `+0x20..+0x2f`: not recovered here.
    pub opaque_20: [u8; FLAGS_OFFSET - LENGTH_LIMIT_OFFSET - core::mem::size_of::<u16>()],
    /// `+0x30`: bit 1 selects a little-endian-u16 prefix; clear selects a byte.
    pub flags: u32,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(LengthPrefixedRequestContext, length_limit) == LENGTH_LIMIT_OFFSET);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(LengthPrefixedRequestContext, flags) == FLAGS_OFFSET);

/// ABI of the unrecovered request consumer at `0x08041038`.
pub type LengthPrefixedRequestDispatch =
    unsafe extern "C" fn(*mut LengthPrefixedRequestOwner, *mut u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_length_prefixed_request_dispatch(
    owner: *mut LengthPrefixedRequestOwner,
    request: *mut u8,
) -> i32 {
    let dispatch: LengthPrefixedRequestDispatch = core::mem::transmute(FIRMWARE_REQUEST_DISPATCH_ADDRESS);
    dispatch(owner, request)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_length_prefixed_request_dispatch(
    _owner: *mut LengthPrefixedRequestOwner,
    _request: *mut u8,
) -> i32 {
    panic!("validated_length_prefixed_request_dispatch requires request consumer 0x08041038")
}

/// Target request-consumer boundary for [`validated_length_prefixed_request_dispatch`].
///
/// No existing ledger entry owns `0x08041038`; this seam is therefore limited
/// to the direct `bl` in this function rather than asserting an identity for
/// that unrecovered callee.
#[cfg(target_os = "none")]
pub static mut LENGTH_PREFIXED_REQUEST_DISPATCH: LengthPrefixedRequestDispatch =
    firmware_length_prefixed_request_dispatch;
#[cfg(not(target_os = "none"))]
pub static mut LENGTH_PREFIXED_REQUEST_DISPATCH: LengthPrefixedRequestDispatch =
    missing_length_prefixed_request_dispatch;

/// Validates a length-prefixed input and dispatches a stack-shaped request.
///
/// # Safety
///
/// `owner_slot` must name a readable owner pointer, whose context is readable
/// through `+0x34`. `input` must be aligned for `u16` when the context selects
/// a wide prefix and contain the complete prefix plus payload. The request
/// consumer receives a 552-byte temporary whose initialized fields are word
/// `+0x04` and bytes `+0x1c..+0x1c+prefix+length`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.validated_length_prefixed_request_dispatch")]
#[inline(never)]
pub unsafe extern "C" fn validated_length_prefixed_request_dispatch(
    owner_slot: *mut *mut LengthPrefixedRequestOwner,
    input: *const u8,
) -> i32 {
    let owner = owner_slot.read();
    let context = (*owner).context;
    let wide_prefix = ((*context).flags & WIDE_LENGTH_FLAG) != 0;
    let length = if wide_prefix {
        input.cast::<u16>().read() as usize
    } else {
        input.read() as usize
    };

    if length > 5 && length > (*context).length_limit as usize {
        return LENGTH_OUT_OF_RANGE;
    }

    let mut request = MaybeUninit::<[u8; REQUEST_STORAGE_SIZE]>::uninit();
    let request = request.as_mut_ptr().cast::<u8>();
    request.add(REQUEST_WORD_OFFSET).cast::<u32>().write(0);

    let copy_length = length + if wide_prefix { 2 } else { 1 };
    let bcopy = ptr::read_volatile(&(crate::libc::bcopy::bcopy as unsafe extern "C" fn(*const u8, *mut u8, usize)));
    bcopy(input, request.add(REQUEST_PAYLOAD_OFFSET), copy_length);

    let dispatch = ptr::addr_of!(LENGTH_PREFIXED_REQUEST_DISPATCH).read_volatile();
    (dispatch)(owner, request) as i16 as i32
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    #[derive(Default)]
    struct DispatchLog {
        calls: u32,
        owner: usize,
        request_word: u32,
        copied: std::vec::Vec<u8>,
        result: i32,
    }

    static DISPATCH_SEAM_LOCK: Mutex<()> = Mutex::new(());
    static DISPATCH_LOG: Mutex<DispatchLog> = Mutex::new(DispatchLog {
        calls: 0,
        owner: 0,
        request_word: 0,
        copied: std::vec::Vec::new(),
        result: 0,
    });

    unsafe extern "C" fn record_dispatch(
        owner: *mut LengthPrefixedRequestOwner,
        request: *mut u8,
    ) -> i32 {
        let mut log = DISPATCH_LOG.lock();
        log.calls += 1;
        log.owner = owner as usize;
        log.request_word = request.add(REQUEST_WORD_OFFSET).cast::<u32>().read();
        let wide_prefix = ((*owner).context.read().flags & WIDE_LENGTH_FLAG) != 0;
        let length = if wide_prefix {
            request.add(REQUEST_PAYLOAD_OFFSET).cast::<u16>().read() as usize
        } else {
            request.add(REQUEST_PAYLOAD_OFFSET).read() as usize
        };
        let copy_length = length + if wide_prefix { 2 } else { 1 };
        log.copied = core::slice::from_raw_parts(request.add(REQUEST_PAYLOAD_OFFSET), copy_length).to_vec();
        log.result
    }

    struct DispatchSeamGuard {
        _lock: MutexGuard<'static, ()>,
        original: LengthPrefixedRequestDispatch,
    }

    impl Drop for DispatchSeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(LENGTH_PREFIXED_REQUEST_DISPATCH).write_volatile(self.original);
            }
        }
    }

    fn install_dispatch(result: i32) -> DispatchSeamGuard {
        let lock = DISPATCH_SEAM_LOCK.lock();
        let original = unsafe { ptr::addr_of!(LENGTH_PREFIXED_REQUEST_DISPATCH).read_volatile() };
        unsafe {
            ptr::addr_of_mut!(LENGTH_PREFIXED_REQUEST_DISPATCH).write_volatile(record_dispatch);
        }
        let mut log = DISPATCH_LOG.lock();
        *log = DispatchLog { result, ..Default::default() };
        drop(log);
        DispatchSeamGuard { _lock: lock, original }
    }

    fn context(flags: u32, length_limit: u16) -> LengthPrefixedRequestContext {
        LengthPrefixedRequestContext {
            opaque_00: [0; LENGTH_LIMIT_OFFSET],
            length_limit,
            opaque_20: [0; FLAGS_OFFSET - LENGTH_LIMIT_OFFSET - core::mem::size_of::<u16>()],
            flags,
        }
    }

    #[test]
    fn byte_prefix_copies_payload_and_dispatches() {
        let _seam = install_dispatch(0x0123);
        let mut context = context(0, 0);
        let mut owner = LengthPrefixedRequestOwner { context: &mut context };
        let mut owner_slot = &mut owner as *mut LengthPrefixedRequestOwner;
        let input = [3u8, 0xa1, 0xb2, 0xc3];

        assert_eq!(unsafe { validated_length_prefixed_request_dispatch(&mut owner_slot, input.as_ptr()) }, 0x0123);

        let log = DISPATCH_LOG.lock();
        assert_eq!(log.calls, 1);
        assert_eq!(log.owner, &mut owner as *mut LengthPrefixedRequestOwner as usize);
        assert_eq!(log.request_word, 0);
        assert_eq!(log.copied, input);
    }

    #[test]
    fn wide_prefix_uses_little_endian_length_and_sign_extends_status() {
        let _seam = install_dispatch(0x0000_ffee);
        let mut context = context(WIDE_LENGTH_FLAG, 7);
        let mut owner = LengthPrefixedRequestOwner { context: &mut context };
        let mut owner_slot = &mut owner as *mut LengthPrefixedRequestOwner;
        let input = [7u8, 0, 1, 2, 3, 4, 5, 6, 7];

        assert_eq!(unsafe { validated_length_prefixed_request_dispatch(&mut owner_slot, input.as_ptr()) }, -18);

        let log = DISPATCH_LOG.lock();
        assert_eq!(log.calls, 1);
        assert_eq!(log.request_word, 0);
        assert_eq!(log.copied, input);
    }

    #[test]
    fn oversized_length_returns_error_without_dispatch() {
        let _seam = install_dispatch(0);
        let mut context = context(WIDE_LENGTH_FLAG, 6);
        let mut owner = LengthPrefixedRequestOwner { context: &mut context };
        let mut owner_slot = &mut owner as *mut LengthPrefixedRequestOwner;
        let input = [7u8, 0, 1, 2, 3, 4, 5, 6, 7];

        assert_eq!(unsafe { validated_length_prefixed_request_dispatch(&mut owner_slot, input.as_ptr()) }, LENGTH_OUT_OF_RANGE);

        let log = DISPATCH_LOG.lock();
        assert_eq!(log.calls, 0);
    }
}
