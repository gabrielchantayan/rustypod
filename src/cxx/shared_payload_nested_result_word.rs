//! Shared payload nested result word — retailOS `FUN_0813e5f4` @ `0x0813e5f4`.
//!
//! Raw ARM occupies exactly 16 bytes, `0x0813e5f4..0x0813e603`; the next
//! independently terminating body begins at `0x0813e604`. Complete A32
//! decoding finds three inbound plain `bl` call sites and zero predicated `bl`
//! forms. It loads the payload's +0x40 result pointer, returning zero when it
//! is NULL and otherwise returning the pointed-to object's +0x14 word.
//! Deliberate deviation: `repr(C)` pointer fields preserve target offsets on
//! ARM while widening naturally for safe host fixtures.

use crate::cxx::shared_payload_result_word::SharedPayload;

/// Returns a shared payload's nested result word, or zero when it has no result.
///
/// # Safety
/// `payload` must be valid and aligned. Its non-NULL result pointer must point
/// to a readable [`SharedPayloadResult`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.shared_payload_nested_result_word")]
#[inline(never)]
pub unsafe extern "C" fn shared_payload_nested_result_word(payload: *const SharedPayload) -> u32 {
    let result = unsafe { (*payload).result };
    if result.is_null() {
        0
    } else {
        unsafe { (*result).value }
    }
}

#[cfg(test)]
mod tests {
    use super::shared_payload_nested_result_word;
    use crate::cxx::shared_payload_result_word::{SharedPayload, SharedPayloadResult};

    #[test]
    fn returns_the_nested_result_word() {
        let result = SharedPayloadResult {
            _prefix: [0; 5],
            value: 0xfeed_beef,
        };
        let payload = SharedPayload {
            _prefix: [0; 16],
            result: core::ptr::addr_of!(result),
        };

        assert_eq!(unsafe { shared_payload_nested_result_word(&payload) }, 0xfeed_beef);
    }

    #[test]
    fn null_result_returns_zero() {
        let payload = SharedPayload {
            _prefix: [0; 16],
            result: core::ptr::null(),
        };

        assert_eq!(unsafe { shared_payload_nested_result_word(&payload) }, 0);
    }
}
