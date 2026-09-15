//! Resolving an object candidate payload.

use crate::four_word_clear::four_word_clear;
use crate::object_word_payload_resolve::{ObjectWordPayloadProcessor, OBJECT_WORD_PAYLOAD_PROCESSOR};

/// Transforms a four-word candidate before it is considered by the object.
pub type ObjectCandidateTransform = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32);
/// Reports whether the object has candidate constraints.
pub type ObjectHasCandidateConstraints = unsafe extern "C" fn(*mut u32) -> bool;
/// Searches constrained candidates, updating `candidate` when one is found.
pub type ObjectFindCandidate = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32) -> bool;
/// Checks whether `candidate` is valid against the four-word object payload.
pub type ObjectCandidateIsValid = unsafe extern "C" fn(*mut u32, *mut u32) -> bool;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_object_candidate_transform(object: *mut u32, input: *mut u32, candidate: *mut u32) {
    let transform: ObjectCandidateTransform = unsafe { core::mem::transmute(0x0829_b7a8usize) };
    unsafe { transform(object, input, candidate) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_object_has_candidate_constraints(object: *mut u32) -> bool {
    let has_constraints: ObjectHasCandidateConstraints = unsafe { core::mem::transmute(0x0829_b224usize) };
    unsafe { has_constraints(object) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_object_find_candidate(object: *mut u32, candidate: *mut u32, output: *mut u32) -> bool {
    let find_candidate: ObjectFindCandidate = unsafe { core::mem::transmute(0x0829_b548usize) };
    unsafe { find_candidate(object, candidate, output) }
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_object_candidate_is_valid(payload: *mut u32, candidate: *mut u32) -> bool {
    let is_valid: ObjectCandidateIsValid = unsafe { core::mem::transmute(0x0829_bda8usize) };
    unsafe { is_valid(payload, candidate) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_candidate_transform(_: *mut u32, _: *mut u32, _: *mut u32) { panic!("object_candidate_payload_resolve requires transform 0x0829b7a8") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_has_candidate_constraints(_: *mut u32) -> bool { panic!("object_candidate_payload_resolve requires constraint check 0x0829b224") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_find_candidate(_: *mut u32, _: *mut u32, _: *mut u32) -> bool { panic!("object_candidate_payload_resolve requires finder 0x0829b548") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_candidate_is_valid(_: *mut u32, _: *mut u32) -> bool { panic!("object_candidate_payload_resolve requires validity check 0x0829bda8") }

#[cfg(target_os = "none")]
const DEFAULT_TRANSFORM: ObjectCandidateTransform = firmware_object_candidate_transform;
#[cfg(not(target_os = "none"))]
const DEFAULT_TRANSFORM: ObjectCandidateTransform = missing_object_candidate_transform;
#[cfg(target_os = "none")]
const DEFAULT_HAS_CONSTRAINTS: ObjectHasCandidateConstraints = firmware_object_has_candidate_constraints;
#[cfg(not(target_os = "none"))]
const DEFAULT_HAS_CONSTRAINTS: ObjectHasCandidateConstraints = missing_object_has_candidate_constraints;
#[cfg(target_os = "none")]
const DEFAULT_FIND_CANDIDATE: ObjectFindCandidate = firmware_object_find_candidate;
#[cfg(not(target_os = "none"))]
const DEFAULT_FIND_CANDIDATE: ObjectFindCandidate = missing_object_find_candidate;
#[cfg(target_os = "none")]
const DEFAULT_IS_VALID: ObjectCandidateIsValid = firmware_object_candidate_is_valid;
#[cfg(not(target_os = "none"))]
const DEFAULT_IS_VALID: ObjectCandidateIsValid = missing_object_candidate_is_valid;

/// Target-only dependencies which have no names.yaml ports. Host tests replace
/// these seams with behavioral models.
pub static mut OBJECT_CANDIDATE_TRANSFORM: ObjectCandidateTransform = DEFAULT_TRANSFORM;
pub static mut OBJECT_HAS_CANDIDATE_CONSTRAINTS: ObjectHasCandidateConstraints = DEFAULT_HAS_CONSTRAINTS;
pub static mut OBJECT_FIND_CANDIDATE: ObjectFindCandidate = DEFAULT_FIND_CANDIDATE;
pub static mut OBJECT_CANDIDATE_IS_VALID: ObjectCandidateIsValid = DEFAULT_IS_VALID;

/// object_candidate_payload_resolve — original: `FUN_0829b3d0` @ **0x0829b3d0**
/// (**140 bytes exactly**, `0x0829b3d0..0x0829b458`; the separately linked next
/// function begins at `0x0829b45c`).
///
/// Raw ARM words contain six outbound unconditional `bl` instructions and no
/// predicated calls: four_word_clear (0x08158cf0), the transform (0x0829b7a8),
/// constraint check (0x0829b224), constrained finder (0x0829b548), validity
/// check (0x0829bda8), and payload processor (0x0829b804). Five inbound call
/// sites are plain `bl`; none is predicated. The function clears a four-word
/// candidate, transforms the input record into it, then either accepts the
/// constrained finder result or validates the candidate against object words
/// 7..10. On fallback success it copies those four object words to `output`
/// before processing them; it returns one on success and zero on failed
/// fallback validation.
///
/// Deliberate deviations: the four unported callees are explicit target-address
/// seams, while the existing 0x0829b804 processor seam is reused. This retains
/// stock target dispatch and permits host behavioral tests without inventing
/// callee implementations.
///
/// # Safety
/// `object` must be valid for eleven aligned `u32` words, and `input` and
/// `output` must each be valid for four aligned `u32` words. The firmware has
/// no NULL checks; aliased input/output retain the original stack-candidate
/// behavior.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_candidate_payload_resolve(object: *mut u32, input: *mut u32, output: *mut u32) -> u32 {
    let mut candidate = [0u32; 4];
    unsafe { four_word_clear(candidate.as_mut_ptr()) };
    let transform = unsafe { core::ptr::addr_of_mut!(OBJECT_CANDIDATE_TRANSFORM).read_volatile() };
    unsafe { transform(object, input, candidate.as_mut_ptr()) };
    let has_constraints = unsafe { core::ptr::addr_of_mut!(OBJECT_HAS_CANDIDATE_CONSTRAINTS).read_volatile() };
    if !unsafe { has_constraints(object) } {
        let find_candidate = unsafe { core::ptr::addr_of_mut!(OBJECT_FIND_CANDIDATE).read_volatile() };
        if unsafe { find_candidate(object, candidate.as_mut_ptr(), output) } { return 1; }
    }
    let is_valid = unsafe { core::ptr::addr_of_mut!(OBJECT_CANDIDATE_IS_VALID).read_volatile() };
    if !unsafe { is_valid(object.add(7), candidate.as_mut_ptr()) } { return 0; }
    let payload = unsafe {
        [
            object.add(7).read(),
            object.add(8).read(),
            object.add(9).read(),
            object.add(10).read(),
        ]
    };
    unsafe {
        output.write(payload[0]);
        output.add(1).write(payload[1]);
        output.add(2).write(payload[2]);
        output.add(3).write(payload[3]);
    }
    let processor: ObjectWordPayloadProcessor = unsafe { core::ptr::addr_of_mut!(OBJECT_WORD_PAYLOAD_PROCESSOR).read_volatile() };
    unsafe { processor(object, output) };
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRAINED: bool = false;
    static mut FIND_RESULT: bool = false;
    static mut VALID: bool = false;
    static mut PROCESS_CALLS: u32 = 0;
    static mut SEEN_CANDIDATE: [u32; 4] = [0; 4];

    unsafe extern "C" fn transform(_: *mut u32, input: *mut u32, candidate: *mut u32) { unsafe { for i in 0..4 { candidate.add(i).write(input.add(i).read() ^ 0xaaaa_0000); } } }
    unsafe extern "C" fn constrained(_: *mut u32) -> bool { unsafe { CONSTRAINED } }
    unsafe extern "C" fn find(_: *mut u32, candidate: *mut u32, output: *mut u32) -> bool { unsafe { SEEN_CANDIDATE = [candidate.read(), candidate.add(1).read(), candidate.add(2).read(), candidate.add(3).read()]; if FIND_RESULT { output.write(0xf1); output.add(1).write(0xf2); output.add(2).write(0xf3); output.add(3).write(0xf4); } FIND_RESULT } }
    unsafe extern "C" fn valid(_: *mut u32, _: *mut u32) -> bool { unsafe { VALID } }
    unsafe extern "C" fn process(_: *mut u32, words: *mut u32) { unsafe { PROCESS_CALLS += 1; words.write(words.read() + 1); } }

    struct Guard(ObjectCandidateTransform, ObjectHasCandidateConstraints, ObjectFindCandidate, ObjectCandidateIsValid, ObjectWordPayloadProcessor);
    impl Drop for Guard { fn drop(&mut self) { unsafe { OBJECT_CANDIDATE_TRANSFORM = self.0; OBJECT_HAS_CANDIDATE_CONSTRAINTS = self.1; OBJECT_FIND_CANDIDATE = self.2; OBJECT_CANDIDATE_IS_VALID = self.3; OBJECT_WORD_PAYLOAD_PROCESSOR = self.4; } } }
    unsafe fn install() -> Guard { unsafe { let guard = Guard(OBJECT_CANDIDATE_TRANSFORM, OBJECT_HAS_CANDIDATE_CONSTRAINTS, OBJECT_FIND_CANDIDATE, OBJECT_CANDIDATE_IS_VALID, OBJECT_WORD_PAYLOAD_PROCESSOR); OBJECT_CANDIDATE_TRANSFORM = transform; OBJECT_HAS_CANDIDATE_CONSTRAINTS = constrained; OBJECT_FIND_CANDIDATE = find; OBJECT_CANDIDATE_IS_VALID = valid; OBJECT_WORD_PAYLOAD_PROCESSOR = process; guard } }

    #[test]
    fn finder_success_bypasses_fallback() {
        let _lock = LOCK.lock(); let _guard = unsafe { install() };
        unsafe { CONSTRAINED = false; FIND_RESULT = true; VALID = false; PROCESS_CALLS = 0; }
        let mut object = [0u32; 11]; let mut input = [1, 2, 3, 4]; let mut output = [0; 4];
        assert_eq!(unsafe { object_candidate_payload_resolve(object.as_mut_ptr(), input.as_mut_ptr(), output.as_mut_ptr()) }, 1);
        assert_eq!(output, [0xf1, 0xf2, 0xf3, 0xf4]); assert_eq!(unsafe { PROCESS_CALLS }, 0); assert_eq!(unsafe { SEEN_CANDIDATE }, [0xaaaa_0001, 0xaaaa_0002, 0xaaaa_0003, 0xaaaa_0004]);
    }

    #[test]
    fn skipped_finder_snapshots_payload_before_overlapping_output() {
        let _lock = LOCK.lock(); let _guard = unsafe { install() };
        unsafe { CONSTRAINED = true; FIND_RESULT = true; VALID = true; PROCESS_CALLS = 0; }
        let mut object = [0u32; 12]; object[7..11].copy_from_slice(&[10, 20, 30, 40]); let mut input = [0; 4];
        let output = unsafe { object.as_mut_ptr().add(8) };
        assert_eq!(unsafe { object_candidate_payload_resolve(object.as_mut_ptr(), input.as_mut_ptr(), output) }, 1);
        assert_eq!(&object[7..12], &[10, 11, 20, 30, 40]); assert_eq!(unsafe { PROCESS_CALLS }, 1);
    }

    #[test]
    fn invalid_fallback_preserves_output() {
        let _lock = LOCK.lock(); let _guard = unsafe { install() };
        unsafe { CONSTRAINED = false; FIND_RESULT = false; VALID = false; PROCESS_CALLS = 0; }
        let mut object = [0u32; 11]; let mut input = [0; 4]; let mut output = [9, 8, 7, 6];
        assert_eq!(unsafe { object_candidate_payload_resolve(object.as_mut_ptr(), input.as_mut_ptr(), output.as_mut_ptr()) }, 0);
        assert_eq!(output, [9, 8, 7, 6]); assert_eq!(unsafe { PROCESS_CALLS }, 0);
    }
}
