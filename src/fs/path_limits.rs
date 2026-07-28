//! path_lengths_ok — original: `FUN_081bd910` @ 0x081bd910 (96 bytes;
//! 14 call sites, binary-scanned, all in the file-path layer
//! @ 0x081bc9f8..0x081bded8 — the cluster that owns the
//! "iPod_Control/Device/PlayCounts" literal @ 0x081bc840).
//!
//! Algorithm: validate a NUL-terminated path against FAT/Win32-style
//! length limits. Walk the string once; at every separator (`\`, `/` or
//! `:`) check the just-finished component's length — 256 or more chars
//! fails immediately. At the NUL, pass only if the final component is
//! also under 256 chars *and* the whole path is under 260 chars
//! (MAX_PATH). A null pointer fails.
//!
//! The first argument is the owning object's `this`; the original never
//! reads it (r0 is overwritten before use), so the port ignores it too.

/// Returns 1 if `path` is non-null, every `\`/`/`/`:`-separated
/// component is at most 255 bytes, and the total length is at most 259
/// bytes; else 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_lengths_ok(_this: usize, path: *const u8) -> u32 {
    if path.is_null() {
        return 0;
    }
    let mut component_start = 0isize;
    let mut i = 0isize;
    loop {
        let c = path.offset(i).read_volatile();
        if c == 0 {
            break;
        }
        if c == b'\\' || c == b'/' || c == b':' {
            if i - component_start >= 0x100 {
                return 0;
            }
            component_start = i + 1;
        }
        i += 1;
    }
    u32::from(i - component_start < 0x100 && i < 0x104)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;
    use std::vec::Vec;

    fn check(s: &str) -> u32 {
        let mut buf: Vec<u8> = s.as_bytes().to_vec();
        buf.push(0);
        unsafe { path_lengths_ok(0, buf.as_ptr()) }
    }

    #[test]
    fn null_path_fails() {
        assert_eq!(unsafe { path_lengths_ok(0, core::ptr::null()) }, 0);
    }

    #[test]
    fn empty_and_ordinary_paths_pass() {
        assert_eq!(check(""), 1);
        assert_eq!(check("iPod_Control/Device/PlayCounts"), 1);
        assert_eq!(check("a\\b\\c"), 1);
        assert_eq!(check("vol:dir:file"), 1);
    }

    #[test]
    fn component_length_boundary_is_255() {
        let comp255 = "x".repeat(255);
        let comp256 = "x".repeat(256);
        assert_eq!(check(&comp255), 1, "255-char final component passes");
        assert_eq!(check(&comp256), 0, "256-char final component fails");
        // Same boundary for a non-final component.
        assert_eq!(check(&std::format!("{comp255}/f")), 1);
        assert_eq!(check(&std::format!("{comp256}/f")), 0);
    }

    #[test]
    fn total_length_boundary_is_259() {
        // Components stay short via separators; total length is the limit.
        let seg = "abcd/"; // 5 chars
        let path259: String = seg.repeat(52).chars().take(259).collect();
        let path260: String = seg.repeat(52).chars().take(260).collect();
        assert_eq!(path259.len(), 259);
        assert_eq!(check(&path259), 1, "259 chars passes");
        assert_eq!(check(&path260), 0, "260 chars fails");
    }

    #[test]
    fn separator_resets_the_component_counter() {
        // 200 + 200 chars: both components fine, total 401 >= 260 fails.
        let long = "y".repeat(200);
        assert_eq!(check(&std::format!("{long}/{long}")), 0);
        // 100 + 100 + 1 separator = 201 total: passes.
        let mid = "y".repeat(100);
        assert_eq!(check(&std::format!("{mid}/{mid}")), 1);
    }

    #[test]
    fn all_three_separators_count() {
        let comp256 = "z".repeat(256);
        for sep in ['/', '\\', ':'] {
            assert_eq!(check(&std::format!("{comp256}{sep}f")), 0, "sep={sep}");
            assert_eq!(check(&std::format!("a{sep}{comp256}")), 0, "sep={sep}");
        }
    }

    #[test]
    fn adjacent_separators_make_empty_components() {
        assert_eq!(check("a//b"), 1);
        assert_eq!(check("///"), 1);
    }
}
