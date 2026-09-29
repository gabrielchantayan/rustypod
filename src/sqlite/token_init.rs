//! `sqlite3TokenInit` — original: `FUN_08369074` @ 0x08369074 (52 bytes;
//! 2 inbound plain `bl` call sites, no predicated inbound `bl`, binary-scanned).
//!
//! Raw ARM establishes the exact extent 0x08369074..0x083690a8: store `text`
//! at Token +0, use zero for NULL or call `strlen` @ 0x08392478 otherwise,
//! then store `length << 1` at Token +4. The packed dynamic bit is therefore
//! always clear. The body has one unconditional outbound `bl` to `strlen` and
//! no predicated calls.
//!
//! Deliberate deviation: Token is represented as two `u32` words rather than
//! a Rust pointer field, preserving the retail 32-bit +0/+4 layout on 64-bit
//! host tests.

use crate::libc::strlen::strlen;

/// Initialize the two-word retail SQLite `Token` from a NUL-terminated string.
///
/// `token` must point to two writable 32-bit words. `text` may be NULL; a
/// non-NULL value must point to a readable NUL-terminated byte string.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3TokenInit(token: *mut u32, text: *const u8) {
    token.write(text as usize as u32);
    let length = if text.is_null() { 0 } else { strlen(text) as u32 };
    token.add(1).write(length << 1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn null_text_clears_the_packed_length() {
        let mut token = [0xffff_ffff, 0xffff_ffff];
        unsafe { sqlite3TokenInit(token.as_mut_ptr(), core::ptr::null()) };
        assert_eq!(token, [0, 0]);
    }

    #[test]
    fn stores_pointer_and_even_byte_length() {
        let text = b"identifier\0";
        let mut token = [0, 0xffff_ffff];
        unsafe { sqlite3TokenInit(token.as_mut_ptr(), text.as_ptr()) };
        assert_eq!(token[0], text.as_ptr() as usize as u32);
        assert_eq!(token[1], 20, "length is 10 shifted left one; dyn is clear");
    }

    #[test]
    fn stops_at_the_first_nul_and_clears_stale_dynamic_bit() {
        let text = b"a\0ignored\0";
        let mut token = [0, 0xffff_ffff];
        unsafe { sqlite3TokenInit(token.as_mut_ptr(), text.as_ptr()) };
        assert_eq!(token[1], 2);
    }
}
