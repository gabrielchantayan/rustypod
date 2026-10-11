//! Validated length-prefixed record update: `FUN_0806478c` @ `0x0806478c`.
//! Raw A32 establishes 148 bytes, ending at the next prologue at `0x08064820`.
//! Two inbound plain BL calls (0x0806c870, 0x0806cb40), no predicated BL;
//! three outbound plain BL calls, no predicated BL. Validate the name prefix,
//! copy prefix plus name into a stack request at +0x1c, seed selection word
//! +4, and pass a {data, size, 1} descriptor to consumer 0x08041ae4. After
//! dispatch, publish selection word +4 even on error; validation errors leave
//! output untouched. Return the sign-extended low 16 bits of either status.
//! Deviations: reuse Rust length_prefix_validate and bcopy; the unported,
//! ledger-unowned consumer has a fixed-address device seam and a host seam.
//! Uninitialized request fields remain uninitialized as in retailOS.

use core::{mem::MaybeUninit, ptr};
use super::managed_entry_selector::LengthPrefixedRequestOwner;
use super::length_prefix_validate::length_prefix_validate;

pub type RecordUpdate = unsafe extern "C" fn(
    *mut LengthPrefixedRequestOwner, *mut u8, *const u32, u32,
) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_record_update(owner: *mut LengthPrefixedRequestOwner, request: *mut u8, descriptor: *const u32, size: u32) -> i32 {
    let update: RecordUpdate = core::mem::transmute(0x0804_1ae4usize);
    update(owner, request, descriptor, size)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_record_update(_: *mut LengthPrefixedRequestOwner, _: *mut u8, _: *const u32, _: u32) -> i32 {
    panic!("length_prefixed_record_update requires consumer 0x08041ae4")
}

/// Unrecovered consumer boundary; host users must install an implementation.
pub static mut LENGTH_PREFIXED_RECORD_UPDATE: RecordUpdate = retail_record_update;

/// # Safety
/// Owner slot and context must be readable. Input must contain its complete
/// prefix and name, be halfword aligned in wide mode, and fit the 524-byte
/// name area. Output must be writable after validation succeeds. The consumer
/// may read only initialized request fields and must not retain stack pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn length_prefixed_record_update(
    owner_slot: *mut *mut LengthPrefixedRequestOwner,
    name: *const u8,
    selection: u32,
    data: u32,
    size: u32,
    output: *mut u32,
) -> i32 {
    update_with(owner_slot, name, selection, data, size, output,
        ptr::read_volatile(ptr::addr_of!(LENGTH_PREFIXED_RECORD_UPDATE)))
}

#[inline(always)]
unsafe fn update_with(owner_slot: *mut *mut LengthPrefixedRequestOwner, name: *const u8, selection: u32, data: u32, size: u32, output: *mut u32, update: RecordUpdate) -> i32 {
    let owner = owner_slot.read();
    let context = (*owner).context;
    let mut request = MaybeUninit::<[u32; 138]>::uninit();
    let words = request.as_mut_ptr().cast::<u32>();
    words.add(1).write(selection);
    let descriptor = [data, size, 1];
    let status = length_prefix_validate(name, context) as i32;
    if status != 0 {
        return status as i16 as i32;
    }
    let count = if ptr::read_volatile(ptr::addr_of!((*context).flags)) & 2 == 0 {
        name.read() as usize + 1
    } else {
        name.cast::<u16>().read() as usize + 2
    };
    crate::libc::bcopy::bcopy(name, words.add(7).cast(), count);
    let status = update(owner, words.cast(), descriptor.as_ptr(), size);
    output.write(words.add(1).read());
    status as i16 as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::managed_entry_selector::LengthPrefixedRequestContext;

    unsafe extern "C" fn replace_selection(_: *mut LengthPrefixedRequestOwner, request: *mut u8, descriptor: *const u32, _: u32) -> i32 {
        // A consumer decision based on the copied name, not on forwarded values.
        let name = request.add(0x1c);
        let wide = name.add(1).read() == 0;
        let end = if wide { name.cast::<u16>().read() as usize + 2 } else { name.read() as usize + 1 };
        assert_eq!(name.add(end - 1).read(), 0xa7);
        assert_eq!(descriptor.add(2).read(), 1);
        request.cast::<u32>().add(1).write(0xdecafbad);
        0x1234ffce
    }

    #[test]
    fn invalid_prefix_preserves_output_and_never_dispatches() {
        for wide in [false, true] {
            let mut context = LengthPrefixedRequestContext { opaque_00: [0; 0x1e], length_limit: 9, opaque_20: [0; 0x10], flags: if wide { 2 } else { 0 } };
            let mut owner = LengthPrefixedRequestOwner { context: &mut context };
            let mut slot = &mut owner as *mut _;
            for length in [0u16, 5, 10, 255] {
                let mut output = 0x11223344;
                let status = unsafe { update_with(&mut slot, (&length as *const u16).cast(), 17, 0, 0, &mut output, retail_record_update) };
                assert_eq!(status, 0x30e);
                assert_eq!(output, 0x11223344);
            }
        }
    }

    #[test]
    fn narrow_and_wide_names_publish_selection_even_on_signed_error() {
        for wide in [false, true] {
            for length in [6usize, 9, 255] {
                let mut context = LengthPrefixedRequestContext { opaque_00: [0; 0x1e], length_limit: 255, opaque_20: [0; 0x10], flags: if wide { 2 } else { 0 } };
                let mut owner = LengthPrefixedRequestOwner { context: &mut context };
                let mut slot = &mut owner as *mut _;
                let mut input = [0x5555u16; 262];
                let bytes = input.as_mut_ptr().cast::<u8>();
                unsafe {
                    if wide { input[0] = length as u16; } else { bytes.write(length as u8); }
                    bytes.add(length + if wide { 2 } else { 1 } - 1).write(0xa7);
                    let mut output = 0;
                    assert_eq!(update_with(&mut slot, bytes, 17, 0, 0, &mut output, replace_selection), -50);
                    assert_eq!(output, 0xdecafbad);
                }
            }
        }
    }
}
