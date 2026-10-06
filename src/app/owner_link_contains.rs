//! `owner_link_contains` — FUN_081685d0 @ 0x081685d0, true size 44 bytes.
//!
//! Raw A32 ends with bx lr at 0x081685f8; the next function starts with
//! push {r4,r5,r6,lr} at 0x081685fc. Whole-image aligned decoding verifies
//! two incoming plain BLs (0x08168420, 0x08168574), zero predicated BLs.
//! The body has no calls. Snapshot end at owner+0x18 and begin at +0x14,
//! scan aligned u32 identity words until equality or end, and return 0/1.
//! Deliberate deviations: host range pointers widen in the repr(C) prefix;
//! firmware offsets remain +0x14/+0x18. No target behavioral deviations.

/// Owner prefix through its registered-link vector bounds.
#[repr(C)]
pub struct OwnerLinkRange {
    pub prefix: [u32; 5],
    pub begin: *const u32,
    pub end: *const u32,
}

/// # Safety
/// `owner` must be aligned and readable. Its bounds must describe one aligned
/// readable u32 range; equal bounds need not be dereferenceable. The owner and
/// range must not be mutated during this call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_link_contains(owner: *const OwnerLinkRange, link: u32) -> u32 {
    let end = (*owner).end;
    let mut cursor = (*owner).begin;
    while cursor != end {
        if cursor.read() == link {
            return 1;
        }
        cursor = cursor.add(1);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_null_or_nonnull_bounds_are_not_dereferenced() {
        for bound in [core::ptr::null(), core::ptr::NonNull::<u32>::dangling().as_ptr()] {
            let owner = OwnerLinkRange { prefix: [u32::MAX; 5], begin: bound, end: bound };
            for link in [0, 1, 0x8000_0000, u32::MAX] {
                assert_eq!(unsafe { owner_link_contains(&owner, link) }, 0);
            }
        }
    }

    #[test]
    fn matches_full_width_words_and_excludes_end_and_prefix() {
        let words = [0, 0x0800_1234, 0x8000_0000, 0x0800_1234, u32::MAX, 0x1234_5678];
        for start in 0..words.len() {
            for end in start..words.len() {
                let owner = OwnerLinkRange {
                    prefix: [0xdead_beef; 5],
                    begin: unsafe { words.as_ptr().add(start) },
                    end: unsafe { words.as_ptr().add(end) },
                };
                for link in words.into_iter().chain([0xdead_beef, 0x0800_1235]) {
                    let expected = u32::from(words[start..end].contains(&link));
                    assert_eq!(unsafe { owner_link_contains(&owner, link) }, expected,
                        "range {start}..{end}, link {link:#x}");
                }
            }
        }
    }
}
