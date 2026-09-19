//! AFM lexical cursor helpers.
//!
//! Ports:
//! - `afm_scan_token_to_delimiter` — original: `FUN_080ade68` @ `0x080ade68`
//!   (128 bytes, `0x080ade68..0x080adee7`; the following function starts at
//!   `0x080adee8`). Raw ARM decoding finds four inbound direct `bl` call
//!   sites, all unconditional (`0x080addb4`, `0x080adddc`, `0x080addf4`,
//!   `0x080b61b4`); no predicated `bl` call sites.
//! - `afm_next_statement_token` — original: `FUN_080add84` @ `0x080add84`
//!   (176 bytes, `0x080add84..0x080ade33`; the following function starts at
//!   `0x080ade34`).
//!
//! `afm_scan_token_to_delimiter` skips horizontal whitespace, returns the
//! first non-whitespace byte's address, then consumes through horizontal
//! whitespace or an AFM delimiter. It sets the cursor state for semicolon,
//! line-end, EOF, and control-Z delimiters. Deliberate deviation: its
//! unported `FUN_080c850c` call is inlined because its raw behavior is fully
//! recovered and the call's return value is unused.
//!
//! `afm_next_statement_token` advances the cursor to the first token of the
//! following statement. Its line-end helper remains a retail target on-device
//! and a host seam in tests.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// AFM parser field layout recovered through the cursor pointer at `+0x04`.
#[repr(C)]
pub struct AfmParser {
    pub context: *mut u8,
    pub scanner: *mut AfmScanner,
}

/// Cursor state consumed by the AFM lexical helpers.
#[repr(C)]
pub struct AfmScanner {
    pub cursor: *mut u8,
    pub unknown_04: u32,
    pub end: *const u8,
    /// `0` active, `1` semicolon, `2` line end, `3` EOF or control-Z.
    pub delimiter_state: u32,
}

type ScannerStep = unsafe extern "C" fn(*mut AfmScanner) -> *mut u8;

/// `afm_scan_token_to_delimiter` — original: `FUN_080ade68` @ `0x080ade68`
/// (128 bytes).
///
/// Skip horizontal whitespace, then consume a token through its delimiter.
/// The cursor and delimiter state use the exact `AfmScanner` offsets from
/// the original. The caller must provide a valid scanner and readable
/// `[cursor, end)` range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn afm_scan_token_to_delimiter(scanner: *mut AfmScanner) -> *mut u8 {
    if unsafe { (*scanner).delimiter_state >= 1 } {
        return core::ptr::null_mut();
    }

    loop {
        let byte = if unsafe { (*scanner).cursor.cast_const() < (*scanner).end } {
            let cursor = unsafe { (*scanner).cursor };
            unsafe { (*scanner).cursor = cursor.add(1) };
            unsafe { cursor.read() as u32 }
        } else {
            u32::MAX
        };

        match byte {
            0x20 | 0x09 => continue,
            0x0d | 0x0a => unsafe { (*scanner).delimiter_state = 2 },
            0x3b => unsafe { (*scanner).delimiter_state = 1 },
            u32::MAX | 0x1a => unsafe { (*scanner).delimiter_state = 3 },
            _ => {
                let token_start = unsafe { (*scanner).cursor.sub(1) };
                loop {
                    let byte = if unsafe { (*scanner).cursor.cast_const() < (*scanner).end } {
                        let cursor = unsafe { (*scanner).cursor };
                        unsafe { (*scanner).cursor = cursor.add(1) };
                        unsafe { cursor.read() as u32 }
                    } else {
                        u32::MAX
                    };
                    match byte {
                        0x20 | 0x09 => return token_start,
                        0x0d | 0x0a => unsafe { (*scanner).delimiter_state = 2 },
                        0x3b => unsafe { (*scanner).delimiter_state = 1 },
                        u32::MAX | 0x1a => unsafe { (*scanner).delimiter_state = 3 },
                        _ => continue,
                    }
                    return token_start;
                }
            }
        }
        return core::ptr::null_mut();
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn scan_to_line_end(scanner: *mut AfmScanner) -> *mut u8 {
    let step: ScannerStep = unsafe { core::mem::transmute(0x080c_84a4usize) };
    unsafe { step(scanner) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_scanner_step(scanner: *mut AfmScanner) -> *mut u8 {
    unsafe { (*scanner).delimiter_state = 3 };
    core::ptr::null_mut()
}

/// Host seam for the unported line-end helper.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct AfmTokenScannerOps {
    pub scan_to_line_end: ScannerStep,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_AFM_TOKEN_SCANNER_OPS: AfmTokenScannerOps =
    AfmTokenScannerOps { scan_to_line_end: unavailable_scanner_step };

#[cfg(not(target_os = "none"))]
pub static mut AFM_TOKEN_SCANNER_OPS: AfmTokenScannerOps = DEFAULT_AFM_TOKEN_SCANNER_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn scan_to_line_end(scanner: *mut AfmScanner) -> *mut u8 {
    let step = unsafe { core::ptr::read_volatile(addr_of!(AFM_TOKEN_SCANNER_OPS.scan_to_line_end)) };
    unsafe { step(scanner) }
}

/// Advance an AFM scanner to the first token of the following statement.
///
/// `parser` and its scanner must be valid. `length`, when non-NULL, receives
/// the exact token length. The returned token is within `scanner.cursor`'s
/// readable range or NULL at end-of-input.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn afm_next_statement_token(
    parser: *mut AfmParser,
    next_line: u32,
    length: *mut u32,
) -> *mut u8 {
    let scanner = unsafe { (*parser).scanner };

    let token_start = if next_line == 0 {
        loop {
            while unsafe { (*scanner).delimiter_state < 1 } {
                unsafe { afm_scan_token_to_delimiter(scanner) };
            }

            unsafe { (*scanner).delimiter_state = 0 };
            let token_start = unsafe { afm_scan_token_to_delimiter(scanner) };
            if !token_start.is_null()
                || unsafe { (*scanner).delimiter_state >= 3 }
                || unsafe { (*scanner).delimiter_state < 1 }
            {
                break token_start;
            }
        }
    } else {
        loop {
            if unsafe { (*scanner).delimiter_state < 2 } {
                unsafe { scan_to_line_end(scanner) };
            }

            unsafe { (*scanner).delimiter_state = 0 };
            let token_start = unsafe { afm_scan_token_to_delimiter(scanner) };
            if !token_start.is_null()
                || unsafe { (*scanner).delimiter_state >= 3 }
                || unsafe { (*scanner).delimiter_state < 2 }
            {
                break token_start;
            }
        }
    };

    if !length.is_null() {
        let token_length = if token_start.is_null() {
            0
        } else {
            let cursor = unsafe { (*scanner).cursor as usize };
            cursor.wrapping_sub(token_start as usize).wrapping_sub(1) as u32
        };
        unsafe { length.write(token_length) };
    }

    token_start
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of_mut, null_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn next_non_horizontal_space(scanner: *mut AfmScanner) -> u32 {
        if unsafe { (*scanner).delimiter_state >= 1 } {
            return b';' as u32;
        }

        loop {
            let byte = if unsafe { (*scanner).cursor.cast_const() < (*scanner).end } {
                let byte = unsafe { (*scanner).cursor.read() };
                unsafe { (*scanner).cursor = (*scanner).cursor.wrapping_add(1) };
                byte as u32
            } else {
                u32::MAX
            };
            match byte {
                32 | 9 => continue,
                13 | 10 => unsafe { (*scanner).delimiter_state = 2 },
                59 => unsafe { (*scanner).delimiter_state = 1 },
                u32::MAX | 0x1a => unsafe { (*scanner).delimiter_state = 3 },
                _ => {}
            }
            return byte;
        }
    }


    unsafe extern "C" fn recovered_scan_to_line_end(scanner: *mut AfmScanner) -> *mut u8 {
        unsafe { next_non_horizontal_space(scanner) };
        if unsafe { (*scanner).delimiter_state >= 2 } {
            return null_mut();
        }
        let line_start = unsafe { (*scanner).cursor.wrapping_sub(1) };

        loop {
            let byte = if unsafe { (*scanner).cursor.cast_const() < (*scanner).end } {
                let byte = unsafe { (*scanner).cursor.read() };
                unsafe { (*scanner).cursor = (*scanner).cursor.wrapping_add(1) };
                byte as u32
            } else {
                u32::MAX
            };
            match byte {
                13 | 10 => unsafe { (*scanner).delimiter_state = 2 },
                u32::MAX | 0x1a => unsafe { (*scanner).delimiter_state = 3 },
                _ => continue,
            }
            return line_start;
        }
    }

    fn install_recovered_scanners() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            addr_of_mut!(AFM_TOKEN_SCANNER_OPS).write(AfmTokenScannerOps {
                scan_to_line_end: recovered_scan_to_line_end,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(AFM_TOKEN_SCANNER_OPS).write(DEFAULT_AFM_TOKEN_SCANNER_OPS) };
        drop(guard);
    }

    fn fixture(bytes: &mut [u8]) -> (AfmParser, AfmScanner) {
        let mut scanner = AfmScanner {
            cursor: bytes.as_mut_ptr(),
            unknown_04: 0,
            end: unsafe { bytes.as_ptr().add(bytes.len()) },
            delimiter_state: 0,
        };
        let parser = AfmParser { context: null_mut(), scanner: &mut scanner };
        (parser, scanner)
    }

    #[test]
    fn token_scanner_skips_horizontal_space_and_stops_before_it() {
        let mut bytes = *b" \tToken next";
        let (_, mut scanner) = fixture(&mut bytes);

        let token = unsafe { afm_scan_token_to_delimiter(&mut scanner) };

        assert_eq!(unsafe { core::slice::from_raw_parts(token, 5) }, b"Token");
        assert_eq!(unsafe { scanner.cursor.offset_from(bytes.as_mut_ptr()) }, 8);
        assert_eq!(scanner.delimiter_state, 0);
    }

    #[test]
    fn token_scanner_records_semicolon_and_line_end_delimiters() {
        let mut semicolon = *b"one;";
        let (_, mut scanner) = fixture(&mut semicolon);
        assert_eq!(unsafe { afm_scan_token_to_delimiter(&mut scanner) }, semicolon.as_mut_ptr());
        assert_eq!(scanner.delimiter_state, 1);

        let mut line = *b"two\n";
        let (_, mut scanner) = fixture(&mut line);
        assert_eq!(unsafe { afm_scan_token_to_delimiter(&mut scanner) }, line.as_mut_ptr());
        assert_eq!(scanner.delimiter_state, 2);
    }

    #[test]
    fn token_scanner_handles_control_z_and_end_of_input() {
        let mut control_z = *b"\x1a";
        let (_, mut scanner) = fixture(&mut control_z);
        assert!(unsafe { afm_scan_token_to_delimiter(&mut scanner) }.is_null());
        assert_eq!(scanner.delimiter_state, 3);

        let mut empty = [];
        let (_, mut scanner) = fixture(&mut empty);
        assert!(unsafe { afm_scan_token_to_delimiter(&mut scanner) }.is_null());
        assert_eq!(scanner.delimiter_state, 3);
    }

    #[test]
    fn returns_the_first_token_after_a_semicolon_statement_boundary() {
        let guard = install_recovered_scanners();
        let mut bytes = *b"ignored 1;Target ";
        let (mut parser, mut scanner) = fixture(&mut bytes);
        parser.scanner = &mut scanner;
        let mut length = u32::MAX;

        let token = unsafe { afm_next_statement_token(&mut parser, 0, &mut length) };

        assert_eq!(unsafe { core::slice::from_raw_parts(token, length as usize) }, b"Target");
        assert_eq!(unsafe { scanner.cursor.offset_from(bytes.as_mut_ptr()) }, bytes.len() as isize);
        restore_default(guard);
    }

    #[test]
    fn next_line_discards_the_current_line_even_when_it_has_a_semicolon() {
        let guard = install_recovered_scanners();
        let mut bytes = *b"skip; still\nWanted ";
        let (mut parser, mut scanner) = fixture(&mut bytes);
        parser.scanner = &mut scanner;
        let mut length = u32::MAX;

        let token = unsafe { afm_next_statement_token(&mut parser, 1, &mut length) };

        assert_eq!(unsafe { core::slice::from_raw_parts(token, length as usize) }, b"Wanted");
        assert_eq!(scanner.delimiter_state, 0);
        restore_default(guard);
    }

    #[test]
    fn end_of_input_returns_null_and_writes_zero_length() {
        let guard = install_recovered_scanners();
        let mut bytes = *b"trailing";
        let (mut parser, mut scanner) = fixture(&mut bytes);
        parser.scanner = &mut scanner;
        let mut length = u32::MAX;

        let token = unsafe { afm_next_statement_token(&mut parser, 0, &mut length) };

        assert!(token.is_null());
        assert_eq!(length, 0);
        assert_eq!(scanner.delimiter_state, 3);
        restore_default(guard);
    }

    #[test]
    fn null_length_does_not_suppress_scanner_progress() {
        let guard = install_recovered_scanners();
        let mut bytes = *b"prior; next ";
        let (mut parser, mut scanner) = fixture(&mut bytes);
        parser.scanner = &mut scanner;

        let token = unsafe { afm_next_statement_token(&mut parser, 0, null_mut()) };

        assert_eq!(unsafe { core::slice::from_raw_parts(token, 4) }, b"next");
        assert_eq!(unsafe { scanner.cursor.offset_from(bytes.as_mut_ptr()) }, bytes.len() as isize);
        restore_default(guard);
    }
}
