//! Restore SQLite's parser authorization context.
//!
//! Original: `FUN_0836f9c8` at load address `0x0836f9c8`, 28 bytes
//! (`0x0836f9c8..0x0836f9e0`). The next separately entered function begins
//! at `0x0836f9e4`. Raw ARM decoding verifies three inbound plain `bl` calls;
//! the function itself contains no `bl` instructions.
//!
//! This is SQLite 3.5.x's `sqlite3AuthContextPop`: if the saved parse is
//! non-NULL, restore its `zAuthContext` from the context and clear the saved
//! parse pointer. A NULL saved parse leaves both context words unchanged. No
//! deliberate deviations.

use super::auth_check::Parse;
use super::auth_context_push::AuthContext;

/// Restore the parser authorization context saved by `sqlite_auth_context_push`.
///
/// # Safety
/// `context` must identify a valid [`AuthContext`]. When its saved parse is
/// non-NULL, it must identify a valid [`Parse`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_auth_context_pop(context: *mut AuthContext) {
    let parse: *mut Parse = (*context).parse;
    if !parse.is_null() {
        (*parse).z_auth_context = (*context).z_auth_context;
        (*context).parse = core::ptr::null_mut();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_context_and_clears_saved_parse() {
        let saved = 0x1234usize as *const u8;
        let mut parse: Parse = unsafe { core::mem::zeroed() };
        parse.z_auth_context = 0x5678usize as *const u8;
        let mut context = AuthContext {
            z_auth_context: saved,
            parse: &mut parse,
        };

        unsafe { sqlite_auth_context_pop(&mut context) };

        assert_eq!(parse.z_auth_context, saved);
        assert!(context.parse.is_null());
    }

    #[test]
    fn null_saved_parse_leaves_context_unchanged() {
        let saved = 0x1234usize as *const u8;
        let mut context = AuthContext {
            z_auth_context: saved,
            parse: core::ptr::null_mut(),
        };

        unsafe { sqlite_auth_context_pop(&mut context) };

        assert_eq!(context.z_auth_context, saved);
        assert!(context.parse.is_null());
    }
}
