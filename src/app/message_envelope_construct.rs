//! Kind-zero message envelope constructor @ 0x0825790c.
//! True extent: 76 bytes (72 instruction bytes and a four-byte vtable literal),
//! ending at the real function boundary 0x08257958. Two plain BL instructions,
//! zero predicated BL instructions; two plain inbound BL sites, zero predicated.
//! Clears only the kind byte at +4, installs vtable 0x089a75a8, allocates a
//! 16-byte nested message, constructs it with (code, data, length), stores the
//! constructor's return at +8, and returns the original envelope.
//! Deliberate deviations: operator_new uses the existing Rust heap port; the
//! unported nested-message constructor @ 0x08257bcc remains a resident ABI
//! seam. Hosts must install that seam. Target pointer words stay u32 on hosts;
//! no allocation-failure guard or padding initialization is added.

use crate::heap::veneers::operator_new;

pub type NestedMessageConstruct = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> *mut u8;

#[cfg(not(target_os = "none"))]
pub static mut NESTED_MESSAGE_CONSTRUCT: Option<NestedMessageConstruct> = None;

/// Construct a message envelope in twelve bytes of aligned writable storage.
///
/// # Safety
/// `envelope` must be valid for three u32 words. `data` and `length` must
/// satisfy the resident nested-message constructor's source-buffer contract.
/// Hosts must install NESTED_MESSAGE_CONSTRUCT before calling this entry.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_envelope_construct(
    envelope: *mut u32, code: u32, data: u32, length: u32,
) -> *mut u32 {
    #[cfg(target_os = "none")]
    let nested: NestedMessageConstruct = core::mem::transmute(0x0825_7bccusize);
    #[cfg(not(target_os = "none"))]
    let nested = core::ptr::addr_of!(NESTED_MESSAGE_CONSTRUCT).read()
        .expect("install resident nested-message constructor");
    construct(envelope, code, data, length, operator_new, nested)
}

unsafe fn construct(
    envelope: *mut u32, code: u32, data: u32, length: u32,
    allocate: unsafe extern "C" fn(usize) -> *mut u8,
    nested: NestedMessageConstruct,
) -> *mut u32 {
    envelope.cast::<u8>().add(4).write(0);
    envelope.write(0x089a_75a8);
    let storage = allocate(16);
    let message = nested(storage, code, data, length);
    envelope.add(2).write(message as usize as u32);
    envelope
}

/// Return the nested-message word of a kind-zero UI message envelope.
///
/// Original: FUN_08257904 @ 0x08257904, true size 8 bytes, ending at
/// constructor boundary 0x0825790c. Two plain inbound BL sites
/// (0x081d6b04, 0x081d7e9c), zero predicated; no outgoing calls.
/// Raw body: `ldr r0,[r0,#8]; bx lr`. Reads the complete aligned +8 word
/// without inspecting the kind or dereferencing the nested message.
/// Deliberate deviations: returns a fixed-width u32 even on hosts; a
/// dedicated text section prevents folding with message_payload_word.
///
/// # Safety
/// `envelope` must point to three readable, aligned u32 words.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.message_envelope_nested_word")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_envelope_nested_word(envelope: *const u32) -> u32 {
    envelope.add(2).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_word_preserves_null_and_all_pointer_bits_without_tag_dispatch() {
        for payload in [0u32, 1, 0x0800_0000, 0x089a_75b8, 0x8000_0000, u32::MAX] {
            for kind_word in [0u32, 1, 0xa5a5_a500, u32::MAX] {
                let words = [0x089a_75a8, kind_word, payload];
                assert_eq!(unsafe { message_envelope_nested_word(words.as_ptr()) }, payload);
            }
        }
    }

    unsafe extern "C" fn failed_allocation(_: usize) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn null_message(_: *mut u8, _: u32, _: u32, _: u32) -> *mut u8 {
        core::ptr::null_mut()
    }

    #[test]
    fn constructor_preserves_padding_and_neighboring_storage() {
        for pattern in [0u32, 0xffff_ffff, 0x1234_5678, 0xa5a5_a5a5] {
            let mut words = [pattern; 5];
            let envelope = unsafe { words.as_mut_ptr().add(1) };
            let result = unsafe { construct(envelope, 0, 0, 0, failed_allocation, null_message) };
            assert_eq!(result, envelope);
            assert_eq!(words, [pattern, 0x089a_75a8, pattern & !0xff, 0, pattern]);
        }
    }

}
