//! Save and replace SQLite's parser authorization context.
//!
//! Original: `FUN_0836f9e4` at load address `0x0836f9e4`, 24 bytes
//! (`0x0836f9e4..0x0836f9fb`). The next separately entered function begins
//! at `0x0836f9fc`. Its three direct callers comprise one plain `bl` and
//! two predicated `blne` instructions; the function itself contains no `bl`
//! instructions.
//!
//! This is SQLite 3.5.x's `sqlite3AuthContextPush`: save the parse and its
//! current `zAuthContext` in `context`, then install `z_context` for nested
//! trigger/view compilation. A NULL parse is recorded in `context.parse` but
//! leaves `context.z_auth_context` untouched. No deliberate deviations.

use super::auth_check::Parse;

/// SQLite's `AuthContext`, used to restore a nested authorization context.
#[repr(C)]
pub struct AuthContext {
    /// +0x00: saved `Parse.zAuthContext`.
    pub z_auth_context: *const u8,
    /// +0x04: saved parse context.
    pub parse: *mut Parse,
}

#[cfg(target_pointer_width = "32")]
const _AUTH_CONTEXT_Z_AUTH_CONTEXT_OFFSET: [u8; 0x00] =
    [0; core::mem::offset_of!(AuthContext, z_auth_context)];
#[cfg(target_pointer_width = "32")]
const _AUTH_CONTEXT_PARSE_OFFSET: [u8; 0x04] =
    [0; core::mem::offset_of!(AuthContext, parse)];

/// Save `parse`'s authorization context and replace it with `z_context`.
///
/// # Safety
/// `context` must be valid for writes. When `parse` is non-NULL, it must
/// identify a valid [`Parse`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_auth_context_push(
    parse: *mut Parse,
    context: *mut AuthContext,
    z_context: *const u8,
) {
    (*context).parse = parse;
    if !parse.is_null() {
        (*context).z_auth_context = (*parse).z_auth_context;
        (*parse).z_auth_context = z_context;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_and_replaces_a_non_null_parse_context() {
        let previous = 0x1234usize as *const u8;
        let replacement = 0x5678usize as *const u8;
        let mut parse: Parse = unsafe { core::mem::zeroed() };
        parse.z_auth_context = previous;
        let mut context = AuthContext {
            z_auth_context: core::ptr::null(),
            parse: core::ptr::null_mut(),
        };

        unsafe { sqlite_auth_context_push(&mut parse, &mut context, replacement) };

        assert!(core::ptr::eq(context.parse, &mut parse));
        assert_eq!(context.z_auth_context, previous);
        assert_eq!(parse.z_auth_context, replacement);
    }

    #[test]
    fn null_parse_preserves_saved_context() {
        let saved = 0x1234usize as *const u8;
        let mut context = AuthContext {
            z_auth_context: saved,
            parse: 0x5678usize as *mut Parse,
        };

        unsafe { sqlite_auth_context_push(core::ptr::null_mut(), &mut context, core::ptr::null()) };

        assert!(context.parse.is_null());
        assert_eq!(context.z_auth_context, saved);
    }
}
