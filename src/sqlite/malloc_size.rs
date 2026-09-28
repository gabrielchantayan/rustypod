//! SQLite allocation-size lookup.
//!
//! `sqlite3_malloc_size` — original: `FUN_0837d374` @ 0x0837d374
//! (24 bytes, 0x0837d374..0x0837d38c; **2 plain `bl` call sites, 0
//! predicated**, binary-scanned from osos.dec). The raw body is
//! `cmp r0,#0; ldrne r1,[r0,#-4]; subne r0,r0,r1; ldrne r0,[r0,#-8];
//! moveq r0,#0; bx lr`: NULL returns zero; otherwise the final alignment
//! pad word before the payload locates the tracked allocation header, whose
//! first word is the requested signed size. Deliberate deviation: typed
//! raw-pointer reads express the same word accesses without reproducing the
//! ARM predication.

/// `sqlite3MallocSize` @ 0x0837d374: return the requested size stored in a
/// tracked allocation's header, or zero for NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_malloc_size(payload: *mut u8) -> i32 {
    if payload.is_null() {
        return 0;
    }

    let pad = (payload.sub(4) as *const u32).read() as usize;
    (payload.sub(pad).sub(8) as *const i32).read()
}

#[cfg(test)]
mod tests {
    use super::sqlite3_malloc_size;

    #[test]
    fn returns_zero_for_null() {
        assert_eq!(unsafe { sqlite3_malloc_size(core::ptr::null_mut()) }, 0);
    }

    #[test]
    fn finds_size_through_final_alignment_pad() {
        for (pad, size) in [(0usize, 1), (4, 0x1234_5678), (12, -7)] {
            let mut words = [0u32; 8];
            let payload = unsafe { words.as_mut_ptr().cast::<u8>().add(8 + pad) };
            unsafe {
                (payload.sub(pad).sub(8) as *mut i32).write(size);
                (payload.sub(4) as *mut u32).write(pad as u32);
                assert_eq!(sqlite3_malloc_size(payload), size);
            }
        }
    }
}
