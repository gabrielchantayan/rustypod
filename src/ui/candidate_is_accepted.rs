//! Candidate acceptance predicate.

/// `candidate_is_accepted` — original: `FUN_082a6448` @ `0x082a6448`
/// (124 bytes; 4 direct `bl` instructions, all unconditional and unpredicated).
///
/// Raw ARM extent is `0x082a6448..0x082a64c4`; the next independently linked
/// function starts with `push {r4,r10,lr}` at `0x082a64c4`. It first invokes
/// the ported [`crate::ui::object_payload::object_payload_if_available`], then
/// rejects when either opaque retail predicate rejects the candidate or its
/// selected packed field is not one after zero fields are initialized. If all
/// predicates accept, it rejects when bit `0x40` is set in either the payload
/// at `+0x8f` (when present) or the context's target object at `+0x18d`.
///
/// The two remaining opaque predicates' type-level meanings are not recovered;
/// their ABI and return-zero acceptance convention are verified from raw ARM.
/// Target builds use literal veneers to their resident retail addresses. Host
/// tests supply exact ABI seams. Deliberate deviation: the first and third
/// callees are existing Rust ports rather than veneers to their stock bodies.
pub type CandidatePredicate = unsafe extern "C" fn(*const u8) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_candidate_predicate(_candidate: *const u8) -> u32 { 0 }

#[cfg(not(target_arch = "arm"))]
pub static mut CANDIDATE_PREDICATE_A: CandidatePredicate = missing_candidate_predicate;
#[cfg(not(target_arch = "arm"))]
pub static mut CANDIDATE_PREDICATE_B: CandidatePredicate = missing_candidate_predicate;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_candidate_predicate_a(candidate: *const u8) -> u32;
    fn retail_candidate_predicate_b(candidate: *const u8) -> u32;
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_candidate_predicate_a(candidate: *const u8) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(CANDIDATE_PREDICATE_A))(candidate)
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_candidate_predicate_b(candidate: *const u8) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(CANDIDATE_PREDICATE_B))(candidate)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_candidate_predicate_a
retail_candidate_predicate_a:
    ldr pc, [pc, #-4]
    .word 0x08061608
    .globl retail_candidate_predicate_b
retail_candidate_predicate_b:
    ldr pc, [pc, #-4]
    .word 0x0806154c
"#);

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn candidate_is_accepted(context: *const u8, candidate: *const u8, relation: u32) -> u32 {
    let payload = crate::ui::object_payload::object_payload_if_available(candidate);
    if retail_candidate_predicate_a(candidate) != 0
        || retail_candidate_predicate_b(candidate) != 0
        || crate::ui::object_packed_field_is_not_one::object_packed_field_is_not_one(candidate as *mut u8, relation as *const u8)
    {
        return 0;
    }
    if payload != 0 && ((payload as *const u8).add(0x8f).read() & 0x40) != 0 {
        return 0;
    }
    let target = (context.add(4) as *const u32).read() as *const u8;
    ((*target.add(0x18d) & 0x40) == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FIXTURE: *mut u8 = core::ptr::null_mut();
    static mut PREDICATE_A_RESULT: u32 = 0;
    static mut PREDICATE_B_RESULT: u32 = 0;

    unsafe extern "C" fn predicate_a(_candidate: *const u8) -> u32 { PREDICATE_A_RESULT }
    unsafe extern "C" fn predicate_b(_candidate: *const u8) -> u32 { PREDICATE_B_RESULT }

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u8)> {
        if FIXTURE.is_null() {
            FIXTURE = try_map_u32_slab(hints::CANDIDATE_IS_ACCEPTED, 0x1000)?;
        }
        Some((FIXTURE, FIXTURE.add(0x100), FIXTURE.add(0x400)))
    }

    #[test]
    fn accepts_only_when_all_predicates_and_flags_clear() {
        let _lock = TEST_LOCK.lock();
        let Some((context, candidate, payload)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("ui/candidate_is_accepted")); return; };
        unsafe {
            let selector = context.add(0x300);
            CANDIDATE_PREDICATE_A = predicate_a; CANDIDATE_PREDICATE_B = predicate_b;
            PREDICATE_A_RESULT = 0; PREDICATE_B_RESULT = 0;
            selector.write(0); selector.add(1).write(0);
            candidate.add(0x1c).write(0); candidate.add(0x1d).write(0); (candidate.add(0x20) as *mut u32).write(payload as u32);
            payload.add(0x8f).write(0); (context.add(4) as *mut u32).write(context.add(0x200) as u32); context.add(0x200 + 0x18d).write(0);
            assert_eq!(candidate_is_accepted(context, candidate, selector as u32), 1);
            assert_eq!(candidate.add(0x1c).read(), 1);
        }
    }

    #[test]
    fn rejects_each_short_circuit_and_each_flag_source() {
        let _lock = TEST_LOCK.lock();
        let Some((context, candidate, payload)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("ui/candidate_is_accepted")); return; };
        unsafe {
            let selector = context.add(0x300);
            CANDIDATE_PREDICATE_A = predicate_a; CANDIDATE_PREDICATE_B = predicate_b;
            selector.write(0); selector.add(1).write(0);
            candidate.add(0x1c).write(1); candidate.add(0x1d).write(0); (candidate.add(0x20) as *mut u32).write(payload as u32); (context.add(4) as *mut u32).write(context.add(0x200) as u32);
            payload.add(0x8f).write(0); context.add(0x200 + 0x18d).write(0);
            PREDICATE_A_RESULT = 1; PREDICATE_B_RESULT = 0; assert_eq!(candidate_is_accepted(context, candidate, selector as u32), 0);
            PREDICATE_A_RESULT = 0; PREDICATE_B_RESULT = 1; assert_eq!(candidate_is_accepted(context, candidate, selector as u32), 0);
            PREDICATE_B_RESULT = 0; candidate.add(0x1c).write(2); assert_eq!(candidate_is_accepted(context, candidate, selector as u32), 0);
            candidate.add(0x1c).write(1); payload.add(0x8f).write(0x40); assert_eq!(candidate_is_accepted(context, candidate, selector as u32), 0);
            payload.add(0x8f).write(0); context.add(0x200 + 0x18d).write(0x40); assert_eq!(candidate_is_accepted(context, candidate, selector as u32), 0);
        }
    }
}
