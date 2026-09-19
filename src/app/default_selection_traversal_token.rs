//! `default_selection_traversal_token` — original: `FUN_080d6d5c` @
//! 0x080d6d5c (8 bytes, 0x080d6d5c..0x080d6d64). The next real function
//! begins at 0x080d6d64 with `push {r1-r3, lr}`; there is no literal pool.
//!
//! Raw A32 words `e59f0000 e12fff1e` are `ldr r0, [pc] ; bx lr`. At the
//! `ldr`, PC is 0x080d6d64, so the returned word is the next function's
//! instruction encoding, `0xe92d400e`. There are four direct inbound plain
//! `bl` sites (0x080a5b5c, 0x080a5ba4, 0x080a5c3c, 0x080a5d84) and no
//! predicated `bl` sites. The callers pass this opaque word to selection
//! traversal; its concrete identity is not established.
//!
//! Deliberate deviation: none.

/// Word returned by the original PC-relative load.
pub const DEFAULT_SELECTION_TRAVERSAL_TOKEN: u32 = 0xe92d_400e;

/// Returns the opaque default token used by selection traversal callers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn default_selection_traversal_token() -> u32 {
    DEFAULT_SELECTION_TRAVERSAL_TOKEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_word_at_the_original_pc_relative_load_address() {
        assert_eq!(
            unsafe { default_selection_traversal_token() },
            DEFAULT_SELECTION_TRAVERSAL_TOKEN
        );
    }
}
