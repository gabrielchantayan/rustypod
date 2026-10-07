//! Service-handler availability predicate.
//!
//! `service_handler_is_available` — original: `FUN_0818e624` @
//! 0x0818e624 (100 bytes: 24 instructions plus the trailing literal word @
//! 0x0818e684; the next function starts at 0x0818e688). The raw ARM body is
//! definitive; Ghidra's 96-byte extent omits that literal. A complete
//! binary scan of `osos.dec` decoding every ARM `B`/`BL` instruction finds
//! **32 direct, unconditional `bl` call sites** and no predicated calls.
//!
//! Algorithm: obtain the asserting service-manager singleton, require the
//! nonzero `+0x30` gate in the otherwise unnamed global @ 0x089ca8d0, and
//! require `selector < 3`; either failed precondition calls `heap_panic`. It
//! then asks [`service_handler_at`] for the selected handler word and the
//! lifecycle predicate whether that selector's state byte is in
//! 4..=6. It re-reads the global gate after both calls, returning one only
//! when that reloaded gate, the handler word, and the lifecycle result are
//! all nonzero.
//!
//! The lifecycle predicate is ported below. Its firmware table has a host
//! fixture only because 0x08ad0f34 is a runtime-initialized RAM address;
//! firmware reads that table directly.
#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) static SERVICE_HANDLER_AVAILABILITY_OPS_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

use crate::app::service_manager::service_manager_instance_veneer;
#[cfg(target_os = "none")]
use crate::app::service_manager::service_handler_at;
use crate::heap::veneers::heap_panic;
use crate::util::table_find::registry_find_for_slot;
use core::ptr;
#[cfg(test)]
use crate::app::service_manager::SERVICE_MANAGER_INSTANCE;

const HANDLER_TABLE_OFFSET: usize = 4;
const HANDLER_SELECTOR_COUNT: u32 = 3;

/// The observed prefix of the otherwise unnamed global @ 0x089ca8d0.
///
/// Only its `+0x30` word is used here. The surrounding object has no
/// recovered identity, so the field is named for this predicate's role
/// rather than an invented class member name.
#[repr(C)]
struct ServiceHandlerAvailabilityGlobals {
    reserved_00: [u32; 12],
    handler_availability_gate: u32,
}

#[cfg(target_os = "none")]
const SERVICE_HANDLER_AVAILABILITY_GLOBALS: *const ServiceHandlerAvailabilityGlobals =
    0x089c_a8d0 as *const ServiceHandlerAvailabilityGlobals;

#[cfg(not(target_os = "none"))]
static mut HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS: ServiceHandlerAvailabilityGlobals =
    ServiceHandlerAvailabilityGlobals {
        reserved_00: [0; 12],
        handler_availability_gate: 0,
    };

#[inline(always)]
unsafe fn handler_availability_gate() -> u32 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(ptr::addr_of!((*SERVICE_HANDLER_AVAILABILITY_GLOBALS).handler_availability_gate))
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate))
    }
}

/// service_handler_state_is_ready — original: `FUN_08138d8c` @
/// **0x08138d8c** (52 raw bytes: 12 ARM instructions plus the trailing table
/// literal @ 0x08138dbc; 0x08138dc0 begins the distinct next function).
/// Ghidra reports only the 48 instruction bytes. A complete decode of every
/// ARM `B`/`BL` word in `osos.dec` finds **12 direct, unconditional `bl` call
/// sites**, with no predicated `bl` or tail-branch callers.
///
/// Algorithm: reject signed selectors three and above through [`heap_panic`],
/// then ignore `manager`, read the signed state byte from selector's 0x114-byte
/// lifecycle record in the three-record table @ 0x08ad0f34, and return whether
/// its unsigned `(state - 4)` is at most two. Thus states 4, 5, and 6 return
/// one; every other signed byte returns zero.
///
/// Deliberate deviation: host builds replace the firmware RAM table with five
/// records and make its second record selector zero, so tests can safely
/// observe selector -1 as well as the three documented records.
#[repr(C)]
#[derive(Clone, Copy)]
struct ServiceHandlerLifecycleRecord {
    state: i8,
    _padding_1: [u8; 3],
    descriptor_record: u32,
    word_8: u32,
    word_c: u32,
    _remaining: [u8; 0x104],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(ServiceHandlerLifecycleRecord, descriptor_record)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ServiceHandlerLifecycleRecord, word_8)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ServiceHandlerLifecycleRecord, word_c)];
const _: [u8; 0x114] = [0; core::mem::size_of::<ServiceHandlerLifecycleRecord>()];

const SERVICE_HANDLER_LIFECYCLE_RECORD_COUNT: i32 = 3;

#[cfg(target_os = "none")]
const SERVICE_HANDLER_LIFECYCLE_RECORDS: *const ServiceHandlerLifecycleRecord =
    0x08ad_0f34 as *const ServiceHandlerLifecycleRecord;

#[cfg(not(target_os = "none"))]
static mut HOST_SERVICE_HANDLER_LIFECYCLE_RECORDS: [ServiceHandlerLifecycleRecord; 5] =
    [ServiceHandlerLifecycleRecord {
        state: 0,
        _padding_1: [0; 3],
        descriptor_record: 0,
        word_8: 0,
        word_c: 0,
        _remaining: [0; 0x104],
    }; 5];

#[cfg(test)]
pub(crate) static SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

#[inline(always)]
unsafe fn service_handler_lifecycle_records() -> *const ServiceHandlerLifecycleRecord {
    #[cfg(target_os = "none")]
    {
        SERVICE_HANDLER_LIFECYCLE_RECORDS
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of!(HOST_SERVICE_HANDLER_LIFECYCLE_RECORDS).cast::<ServiceHandlerLifecycleRecord>().add(1)
    }
}

/// service_handler_lifecycle_state — original: `FUN_08138b84` @
/// **0x08138b84** (36 raw bytes: eight ARM instructions plus the trailing
/// table literal @ 0x08138ba4; 0x08138ba8 begins the distinct next function).
/// Ghidra reports only the 32 instruction bytes. A complete decode of every
/// ARM `B`/`BL` word in `osos.dec` finds **12 direct, unconditional `bl` call
/// sites**, with no predicated `bl` or tail-branch callers.
///
/// Algorithm: reject signed selectors three and above through [`heap_panic`],
/// then ignore `manager` and return the sign-extended state byte at the start
/// of selector's 0x114-byte lifecycle record in the table @ 0x08ad0f34.
///
/// Deliberate deviation: host builds replace the firmware RAM table with five
/// records and make its second record selector zero, so tests can safely
/// observe selector -1 as well as the three documented records.
///
/// # Safety
///
/// `selector` must name a readable lifecycle record at 0x08ad0f34. The
/// original's signed range check admits negative selectors, which therefore
/// address records before that table.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_lifecycle_state(_manager: *mut u8, selector: i32) -> i32 {
    if selector >= SERVICE_HANDLER_LIFECYCLE_RECORD_COUNT {
        heap_panic();
    }

    let record = service_handler_lifecycle_records().wrapping_offset(selector as isize);
    ptr::read_volatile(ptr::addr_of!((*record).state)) as i32
}
/// service_handler_lifecycle_word_8 — original: `FUN_08138ba8` @
/// **0x08138ba8** (40 raw bytes: nine ARM instructions plus the trailing table
/// literal @ 0x08138bcc; 0x08138bd0 begins the distinct next function).
/// Ghidra reports only the 36 instruction bytes. A complete decode of every
/// ARM `B`/`BL` word in `osos.dec` finds **five direct, unconditional `bl` call
/// sites**, with no predicated `bl` or tail-branch callers.
///
/// Algorithm: ignore `manager`; selectors one and two return their
/// 0x114-byte lifecycle record's 32-bit otherwise-unidentified word at offset
/// `+8`. Every other selector, including negative values, returns zero.
///
/// Deliberate deviation: host builds share the adjacent lifecycle-table
/// fixture; firmware reads the table at 0x08ad0f34 directly.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_lifecycle_word_8(_manager: *mut u8, selector: i32) -> u32 {
    if (selector as u32).wrapping_sub(1) >= 2 {
        return 0;
    }

    let record = service_handler_lifecycle_records().add(selector as usize);
    ptr::read_volatile(ptr::addr_of!((*record).word_8))
}


/// service_handler_lifecycle_select_default_descriptor — original:
/// `FUN_08138c30` @ **0x08138c30** (80 raw bytes: 19 ARM instructions plus
/// the trailing lifecycle-table literal @ 0x08138c7c; 0x08138c80 begins the
/// next function). Ghidra's 76-byte extent omits that literal. A complete
/// decode of every ARM `B`/`BL` word in `osos.dec` finds **9 direct,
/// unconditional `bl` call sites**, with no predicated calls or tail branches.
///
/// Algorithm: reject selector zero and signed selectors three and above with
/// status 9. Every other signed selector looks up registry id zero for that
/// selector, writes the returned record pointer to lifecycle record `+4`,
/// clears `+8` and `+0xc`, and returns zero. The signed guard deliberately
/// admits negative selectors; their ARM shift makes the registry lookup miss,
/// but the pre-table lifecycle record is still cleared.
///
/// Deliberate deviation: host builds use the same five-record lifecycle
/// fixture as the adjacent accessors and retain the target's 32-bit pointer
/// field, so host pointers are stored truncated exactly as device pointers are.
///
/// # Safety
///
/// `selector` must name a writable lifecycle record at 0x08ad0f34. The
/// original's signed range check admits negative selectors, which therefore
/// address records before that table.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_lifecycle_select_default_descriptor(
    manager: *mut u8,
    selector: i32,
) -> u32 {
    if selector == 0 || selector >= SERVICE_HANDLER_LIFECYCLE_RECORD_COUNT {
        return 9;
    }

    let record =
        service_handler_lifecycle_records().wrapping_offset(selector as isize) as *mut ServiceHandlerLifecycleRecord;
    let descriptor_record = registry_find_for_slot(manager, selector as u32, 0) as u32;
    ptr::write_volatile(ptr::addr_of_mut!((*record).descriptor_record), descriptor_record);
    ptr::write_volatile(ptr::addr_of_mut!((*record).word_8), 0);
    ptr::write_volatile(ptr::addr_of_mut!((*record).word_c), 0);
    0
}

/// service_handler_lifecycle_set_format — original: `FUN_08138de8` @
/// **0x08138de8**, 124 bytes (120 instruction bytes and table literal at
/// 0x08138e60; next function starts at 0x08138e64). Raw whole-image BL
/// decoding finds two plain incoming calls and no predicated incoming calls;
/// this body has no plain BL and one signed BLGE to canonical heap_panic.
///
/// Ignore manager, reject signed selectors >=3, and accept only format
/// (1, 0) or (2, 0), with lengths 16 or 20 respectively. Store format,
/// revision, and length at record +0x10..+0x12. Invalid formats clear all
/// three bytes and return 3 without touching output; valid formats write
/// one output byte and return 0. Ghidra's void return is incorrect.
///
/// Deliberate deviation: host builds share the existing lifecycle fixture.
/// No device behavior changes; the signed guard still admits negative slots.
/// Codegen review: match.py reports 30 original versus 50 Rust instructions.
/// LLVM splits format cases, uses MLA for the 0x114 stride and CLZ for the
/// revision-zero test; signed rejection, byte-store order, statuses, and
/// success-only output write remain intact.
///
/// # Safety
/// selector must address a writable lifecycle record, including pre-table
/// records for negative selectors. output must be writable on success only.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_lifecycle_set_format(
    _manager: *mut u8,
    selector: i32,
    format: u32,
    revision: u32,
    output: *mut u8,
) -> u32 {
    if selector >= SERVICE_HANDLER_LIFECYCLE_RECORD_COUNT {
        heap_panic();
    }
    let length = match (format, revision) {
        (1, 0) => 16,
        (2, 0) => 20,
        _ => 0,
    };
    let record = service_handler_lifecycle_records().wrapping_offset(selector as isize)
        as *mut ServiceHandlerLifecycleRecord;
    let fields = ptr::addr_of_mut!((*record)._remaining).cast::<u8>();
    ptr::write_volatile(fields, if length != 0 { format as u8 } else { 0 });
    ptr::write_volatile(fields.add(1), 0);
    ptr::write_volatile(fields.add(2), length);
    if length == 0 {
        return 3;
    }
    ptr::write_volatile(output, length);
    0
}

#[cfg(test)]
mod lifecycle_format_tests {
    use super::*;

    #[test]
    fn formats_update_only_three_record_bytes_and_one_output_byte() {
        let _guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap();
        unsafe {
            for selector in -1..3 {
                for format in [0, 1, 2, 3, 0x101, u32::MAX] {
                    for revision in [0, 1, 0x100, u32::MAX] {
                        let record = service_handler_lifecycle_records()
                            .wrapping_offset(selector as isize) as *mut u8;
                        let mut saved = [0u8; 0x114];
                        ptr::copy_nonoverlapping(record, saved.as_mut_ptr(), saved.len());
                        ptr::write_bytes(record, 0xa5, saved.len());
                        let mut output = [0x7b; 3];
                        let valid = (format == 1 || format == 2) && revision == 0;
                        let expected_length = if valid { if format == 1 { 16 } else { 20 } } else { 0 };
                        let status = service_handler_lifecycle_set_format(
                            ptr::null_mut(), selector, format, revision, output.as_mut_ptr().add(1));
                        assert_eq!(status, if valid { 0 } else { 3 });
                        assert_eq!(output, [0x7b, if valid { expected_length } else { 0x7b }, 0x7b]);
                        for offset in 0..saved.len() {
                            let expected = match offset {
                                0x10 => if valid { format as u8 } else { 0 },
                                0x11 => 0,
                                0x12 => expected_length,
                                _ => 0xa5,
                            };
                            assert_eq!(ptr::read(record.add(offset)), expected);
                        }
                        // Failure must not dereference even a null output.
                        if !valid {
                            assert_eq!(service_handler_lifecycle_set_format(
                                ptr::null_mut(), selector, format, revision, ptr::null_mut()), 3);
                        }
                        ptr::copy_nonoverlapping(saved.as_ptr(), record, saved.len());
                    }
                }
            }
        }
    }

    #[test]
    fn output_alias_is_written_after_record_fields() {
        let _guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap();
        unsafe {
            let record = service_handler_lifecycle_records() as *mut ServiceHandlerLifecycleRecord;
            let fields = ptr::addr_of_mut!((*record)._remaining).cast::<u8>();
            let saved = [ptr::read(fields), ptr::read(fields.add(1)), ptr::read(fields.add(2))];
            assert_eq!(service_handler_lifecycle_set_format(
                ptr::null_mut(), 0, 2, 0, fields), 0);
            assert_eq!([ptr::read(fields), ptr::read(fields.add(1)), ptr::read(fields.add(2))], [20, 0, 20]);
            ptr::copy_nonoverlapping(saved.as_ptr(), fields, 3);
        }
    }
}

/// service_handler_lifecycle_generate_bytes — `FUN_081385e4` @
/// **0x081385e4**, 108 bytes: 104 instruction bytes plus the table literal
/// at 0x0813864c; the next function starts at 0x08138650.
/// Whole-image A32 decoding finds two plain incoming BLs (0x08193370,
/// 0x0819358c), no predicated incoming BLs. Outbound: three plain BLs and
/// one signed BLGE to heap_panic.
///
/// Ignore manager; signed selectors >=3 are fatal (negative selectors
/// remain accepted). Generate length bytes into output through the verified
/// random-byte filler at 0x082cdcb8. On success, clear exactly 255 bytes at
/// lifecycle record +0x14, then copy length bytes from output and return 0.
/// On filler failure, leave the record untouched and return 0x40.
///
/// Deliberate deviations: reuse the host lifecycle fixture and inject only
/// the unported filler on hosts. Target calls its verified two-argument ABI.
/// The IRAM veneers resolve to ported memzero_aligned and __rt_memcpy;
/// volatile function-pointer reads prevent LLVM builtin substitution.
/// Codegen review: 26 original versus 35 Rust instructions; LLVM uses MLA,
/// folds +0x14 into the table base, and emits BLX for the verified seams.
///
/// # Safety
/// output must satisfy the filler and copy contracts for length bytes.
/// selector must address writable storage, including pre-table storage for
/// negative selectors. No length clamp or nonaliasing guard exists in stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_lifecycle_generate_bytes(
    _manager: *mut u8, selector: i32, length: u32, output: *mut u8,
) -> u32 {
    if selector >= SERVICE_HANDLER_LIFECYCLE_RECORD_COUNT {
        heap_panic();
    }
    #[cfg(target_os = "none")]
    let fill: LifecycleRandomFill = core::mem::transmute(0x082c_dcb8usize);
    #[cfg(not(target_os = "none"))]
    let fill = ptr::read(ptr::addr_of!(LIFECYCLE_RANDOM_FILL));
    if fill(output, length) != 0 {
        return 0x40;
    }
    let record = service_handler_lifecycle_records().wrapping_offset(selector as isize);
    let destination = record.cast::<u8>().cast_mut().add(0x14);
    let zero = ptr::read_volatile(&LIFECYCLE_ZERO);
    zero(destination, 255);
    let copy = ptr::read_volatile(&LIFECYCLE_COPY);
    copy(destination, output, length as usize);
    0
}

pub type LifecycleRandomFill = unsafe extern "C" fn(*mut u8, u32) -> u32;
static LIFECYCLE_ZERO: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 =
    crate::memzero::memzero_aligned;
static LIFECYCLE_COPY: unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 =
    crate::rt_memcpy::__rt_memcpy;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lifecycle_random_fill(_output: *mut u8, _length: u32) -> u32 {
    panic!("retailOS random-byte filler requires a host seam");
}

#[cfg(not(target_os = "none"))]
pub static mut LIFECYCLE_RANDOM_FILL: LifecycleRandomFill = missing_lifecycle_random_fill;

#[cfg(test)]
mod lifecycle_generate_tests {
    use super::*;

    unsafe extern "C" fn fill_pattern(output: *mut u8, length: u32) -> u32 {
        for index in 0..length as usize {
            output.add(index).write((index as u8).wrapping_mul(37).wrapping_add(11));
        }
        0
    }

    unsafe extern "C" fn fail_after_write(output: *mut u8, _length: u32) -> u32 {
        output.write(0x19);
        7
    }

    #[test]
    fn generated_bytes_clear_tail_and_preserve_record_boundaries() {
        let _lock = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap();
        unsafe {
            let old_fill = LIFECYCLE_RANDOM_FILL;
            LIFECYCLE_RANDOM_FILL = fill_pattern;
            for selector in -1..3 {
                for length in [0, 1, 3, 4, 16, 20, 254, 255, 256] {
                    let record = service_handler_lifecycle_records()
                        .wrapping_offset(selector as isize).cast::<u8>().cast_mut();
                    let mut saved = [0u8; 0x114];
                    ptr::copy_nonoverlapping(record, saved.as_mut_ptr(), saved.len());
                    ptr::write_bytes(record, 0xa6, 0x114);
                    let mut output = [0x7bu8; 258];
                    assert_eq!(service_handler_lifecycle_generate_bytes(
                        ptr::null_mut(), selector, length, output.as_mut_ptr().add(1)), 0);
                    for index in 0..0x114 {
                        let expected = if index < 0x14 { 0xa6 }
                            else if index - 0x14 < length as usize {
                                ((index - 0x14) as u8).wrapping_mul(37).wrapping_add(11)
                            } else if index < 0x113 { 0 } else { 0xa6 };
                        assert_eq!(record.add(index).read(), expected, "slot {selector}, length {length}, byte {index}");
                    }
                    assert_eq!(output[0], 0x7b);
                    assert_eq!(output[length as usize + 1], 0x7b);
                    ptr::copy_nonoverlapping(saved.as_ptr(), record, saved.len());
                }
            }
            LIFECYCLE_RANDOM_FILL = old_fill;
        }
    }

    #[test]
    fn filler_failure_preserves_record_and_alias_observes_clear_before_copy() {
        let _lock = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap();
        unsafe {
            let old_fill = LIFECYCLE_RANDOM_FILL;
            let record = service_handler_lifecycle_records().cast::<u8>().cast_mut();
            let mut saved = [0u8; 0x114];
            ptr::copy_nonoverlapping(record, saved.as_mut_ptr(), saved.len());
            ptr::write_bytes(record, 0xa6, 0x114);
            LIFECYCLE_RANDOM_FILL = fail_after_write;
            let mut output = [0x7b; 4];
            assert_eq!(service_handler_lifecycle_generate_bytes(
                ptr::null_mut(), 0, 4, output.as_mut_ptr()), 0x40);
            assert_eq!(output, [0x19, 0x7b, 0x7b, 0x7b]);
            assert_eq!(core::slice::from_raw_parts(record, 0x114), &[0xa6; 0x114]);
            LIFECYCLE_RANDOM_FILL = fill_pattern;
            assert_eq!(service_handler_lifecycle_generate_bytes(
                ptr::null_mut(), 0, 20, record.add(0x14)), 0);
            assert_eq!(core::slice::from_raw_parts(record.add(0x14), 255), &[0; 255]);
            ptr::copy_nonoverlapping(saved.as_ptr(), record, saved.len());
            LIFECYCLE_RANDOM_FILL = old_fill;
        }
    }
}

/// # Safety
///
/// `selector` must name a readable lifecycle record at 0x08ad0f34. The
/// original's signed range check admits negative selectors, which therefore
/// address records before that table.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_state_is_ready(_manager: *mut u8, selector: i32) -> u32 {
    if selector >= SERVICE_HANDLER_LIFECYCLE_RECORD_COUNT {
        heap_panic();
    }

    let record = service_handler_lifecycle_records().wrapping_offset(selector as isize);
    let state = ptr::read_volatile(ptr::addr_of!((*record).state)) as i32;
    (((state - 4) as u32) <= 2) as u32
}

#[cfg(test)]
pub(crate) unsafe fn replace_service_handler_lifecycle_state(selector: i32, state: i8) -> i8 {
    let record = service_handler_lifecycle_records().wrapping_offset(selector as isize);
    let previous = ptr::read_volatile(ptr::addr_of!((*record).state));
    ptr::write_volatile(ptr::addr_of_mut!((*(record as *mut ServiceHandlerLifecycleRecord)).state), state);
    previous
}

type HandlerAt = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[derive(Clone, Copy)]
struct ServiceHandlerAvailabilityOps {
    handler_at: HandlerAt,
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_at(table: *mut u8, selector: u32) -> u32 {
    service_handler_at(table.cast(), selector as i32)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_handler_at(_table: *mut u8, _selector: u32) -> u32 {
    0
}


#[cfg(target_os = "none")]
static mut SERVICE_HANDLER_AVAILABILITY_OPS: ServiceHandlerAvailabilityOps =
    ServiceHandlerAvailabilityOps {
        handler_at: firmware_handler_at,
    };

#[cfg(not(target_os = "none"))]
static mut SERVICE_HANDLER_AVAILABILITY_OPS: ServiceHandlerAvailabilityOps =
    ServiceHandlerAvailabilityOps {
        handler_at: unavailable_handler_at,
    };


#[inline(always)]
unsafe fn availability_ops() -> ServiceHandlerAvailabilityOps {
    ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_AVAILABILITY_OPS))
}


/// service_handler_is_available — original: `FUN_0818e624` @ 0x0818e624
/// (100 bytes including literal; 32 direct unconditional `bl` call sites).
///
/// Returns whether the selected service-manager handler is present and its
/// lifecycle state is ready. The gate at 0x089ca900 and selector range are
/// asserting preconditions; each failed condition calls [`heap_panic`]. The
/// gate is deliberately loaded again after the two callee calls, exactly as
/// the original's final `ldr r1,[r6,#0x30]` does.
///
/// # Safety
///
/// The service-manager singleton and its handler table must be initialized.
/// `selector` must be less than three; invalid selectors and a zero global
/// gate are fatal in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_is_available(selector: u32) -> u32 {
    let ops = availability_ops();
    let manager = service_manager_instance_veneer();

    if handler_availability_gate() == 0 || selector >= HANDLER_SELECTOR_COUNT {
        heap_panic();
    }

    let handler = (ops.handler_at)(manager.add(HANDLER_TABLE_OFFSET), selector);
    let state_is_ready = service_handler_state_is_ready(manager, selector as i32);

    (handler_availability_gate() != 0 && handler != 0 && state_is_ready != 0) as u32
}



#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::table_find::{SlotRecord, SLOT_RECORDS, SLOT_RECORDS_LOCK};
    unsafe fn lifecycle_record(selector: i32) -> *mut ServiceHandlerLifecycleRecord {
        service_handler_lifecycle_records().wrapping_offset(selector as isize) as *mut ServiceHandlerLifecycleRecord
    }

    unsafe fn set_lifecycle_record(
        record: *mut ServiceHandlerLifecycleRecord,
        state: i8,
        descriptor_record: u32,
        word_8: u32,
        word_c: u32,
    ) {
        ptr::write_volatile(record, ServiceHandlerLifecycleRecord {
            state,
            _padding_1: [0; 3],
            descriptor_record,
            word_8,
            word_c,
            _remaining: [0; 0x104],
        });
    }

    #[test]
    fn default_descriptor_selection_writes_only_the_three_descriptor_words() {
        let _registry_guard = SLOT_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _lifecycle_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        unsafe {
            let registry = ptr::addr_of_mut!(SLOT_RECORDS) as *mut SlotRecord;
            (*registry.add(17)).id = 0;
            (*registry.add(17)).slot_mask = 0b0000_0010;

            let selected = lifecycle_record(1);
            let missing = lifecycle_record(2);
            let negative = lifecycle_record(-1);
            let selected_before = ptr::read_volatile(selected);
            let missing_before = ptr::read_volatile(missing);
            let negative_before = ptr::read_volatile(negative);
            set_lifecycle_record(selected, -5, 0xdead_beef, 0x1111_1111, 0x2222_2222);
            set_lifecycle_record(missing, 6, 0xdead_beef, 0x3333_3333, 0x4444_4444);
            set_lifecycle_record(negative, -2, 0xdead_beef, 0x5555_5555, 0x6666_6666);

            assert_eq!(service_handler_lifecycle_select_default_descriptor(ptr::null_mut(), 1), 0);
            assert_eq!((*selected).state, -5, "the state byte is not initialized here");
            assert_eq!((*selected).descriptor_record, registry.add(17) as u32);
            assert_eq!((*selected).word_8, 0);
            assert_eq!((*selected).word_c, 0);

            assert_eq!(service_handler_lifecycle_select_default_descriptor(ptr::null_mut(), 2), 0);
            assert_eq!((*missing).state, 6);
            assert_eq!((*missing).descriptor_record, 0, "a missing default is stored as NULL");
            assert_eq!((*missing).word_8, 0);
            assert_eq!((*missing).word_c, 0);

            assert_eq!(service_handler_lifecycle_select_default_descriptor(ptr::null_mut(), -1), 0);
            assert_eq!((*negative).state, -2);
            assert_eq!((*negative).descriptor_record, 0, "the signed guard admits negative selectors");
            assert_eq!((*negative).word_8, 0);
            assert_eq!((*negative).word_c, 0);

            (*registry.add(17)).id = 0;
            (*registry.add(17)).slot_mask = 0;
            ptr::write_volatile(selected, selected_before);
            ptr::write_volatile(missing, missing_before);
            ptr::write_volatile(negative, negative_before);
        }
    }

    #[test]
    fn zero_selector_returns_status_nine_without_touching_the_record() {
        let _lifecycle_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        unsafe {
            let record = lifecycle_record(0);
            let before = ptr::read_volatile(record);
            set_lifecycle_record(record, 7, 0xdead_beef, 0x1111_1111, 0x2222_2222);

            assert_eq!(service_handler_lifecycle_select_default_descriptor(ptr::null_mut(), 0), 9);
            assert_eq!((*record).state, 7);
            assert_eq!((*record).descriptor_record, 0xdead_beef);
            assert_eq!((*record).word_8, 0x1111_1111);
            assert_eq!((*record).word_c, 0x2222_2222);

            ptr::write_volatile(record, before);
        }
    }

    static mut MOCK_MANAGER: *mut u8 = ptr::null_mut();
    static mut MOCK_SELECTOR: u32 = 0;
    static mut MOCK_HANDLER: u32 = 0;
    static mut GATE_AFTER_HANDLER: u32 = 1;
    static mut HANDLER_CALLS: u32 = 0;

    unsafe extern "C" fn mock_handler_at(table: *mut u8, selector: u32) -> u32 {
        assert_eq!(table, MOCK_MANAGER.add(HANDLER_TABLE_OFFSET));
        assert_eq!(selector, MOCK_SELECTOR);
        HANDLER_CALLS += 1;
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(GATE_AFTER_HANDLER);
        MOCK_HANDLER
    }

    unsafe fn install(
        manager: *mut u8,
        selector: u32,
        handler: u32,
        state: i8,
        gate_after_handler: u32,
    ) -> (ServiceHandlerAvailabilityOps, i8) {
        let previous_ops = ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_AVAILABILITY_OPS));
        let previous_state = replace_service_handler_lifecycle_state(selector as i32, state);
        SERVICE_HANDLER_AVAILABILITY_OPS = ServiceHandlerAvailabilityOps {
            handler_at: mock_handler_at,
        };
        MOCK_MANAGER = manager;
        MOCK_SELECTOR = selector;
        MOCK_HANDLER = handler;
        GATE_AFTER_HANDLER = gate_after_handler;
        ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), manager);
        HANDLER_CALLS = 0;
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(1);
        (previous_ops, previous_state)
    }

    unsafe fn restore(previous_ops: ServiceHandlerAvailabilityOps, selector: u32, previous_state: i8) {
        SERVICE_HANDLER_AVAILABILITY_OPS = previous_ops;
        replace_service_handler_lifecycle_state(selector as i32, previous_state);
        MOCK_MANAGER = ptr::null_mut();
        ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut());
        ptr::addr_of_mut!(HOST_SERVICE_HANDLER_AVAILABILITY_GLOBALS.handler_availability_gate)
            .write_volatile(0);
    }

    #[test]
    fn lifecycle_predicate_accepts_only_the_three_ready_states() {
        let _guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        for (selector, state, expected) in [
            (-1, 6, 1),
            (0, -1, 0),
            (1, 3, 0),
            (2, 4, 1),
            (0, 5, 1),
            (1, 6, 1),
            (2, 7, 0),
        ] {
            let previous = unsafe { replace_service_handler_lifecycle_state(selector, state) };
            assert_eq!(
                unsafe { service_handler_state_is_ready(ptr::null_mut(), selector) },
                expected,
                "selector {selector}, state {state}",
            );
            unsafe {
                replace_service_handler_lifecycle_state(selector, previous);
            }
        }
    }

    #[test]
    fn lifecycle_state_returns_the_signed_byte_for_each_admitted_selector() {
        let _guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        for (selector, state) in [(-1, -2), (0, 0), (1, 6), (2, 127)] {
            let previous = unsafe { replace_service_handler_lifecycle_state(selector, state) };
            assert_eq!(
                unsafe { service_handler_lifecycle_state(ptr::null_mut(), selector) },
                state as i32,
                "selector {selector}, state {state}",
            );
            unsafe {
                replace_service_handler_lifecycle_state(selector, previous);
            }
        }
    }

    #[test]
    fn lifecycle_word_8_accepts_only_selectors_one_and_two() {
        let _guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        unsafe {
            let first = lifecycle_record(1);
            let second = lifecycle_record(2);
            let first_before = ptr::read_volatile(first);
            let second_before = ptr::read_volatile(second);
            set_lifecycle_record(first, 0, 0, 0x1234_5678, 0);
            set_lifecycle_record(second, 0, 0, 0x9abc_def0, 0);

            for (selector, expected) in [
                (i32::MIN, 0),
                (-1, 0),
                (0, 0),
                (1, 0x1234_5678),
                (2, 0x9abc_def0),
                (3, 0),
                (i32::MAX, 0),
            ] {
                assert_eq!(
                    service_handler_lifecycle_word_8(ptr::null_mut(), selector),
                    expected,
                    "selector {selector}",
                );
            }

            ptr::write_volatile(first, first_before);
            ptr::write_volatile(second, second_before);
        }
    }

    #[test]
    fn accepts_both_edge_selectors_when_handler_and_state_are_nonzero() {
        let _ops_guard = SERVICE_HANDLER_AVAILABILITY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];

        for selector in [0, HANDLER_SELECTOR_COUNT - 1] {
            let (previous_ops, previous_state) =
                unsafe { install(manager.as_mut_ptr().cast(), selector, 0x1000, 6, 1) };
            assert_eq!(unsafe { service_handler_is_available(selector) }, 1);
            unsafe {
                assert_eq!(HANDLER_CALLS, 1);
                restore(previous_ops, selector, previous_state);
            }
        }
    }

    #[test]
    fn evaluates_lifecycle_state_when_handler_is_absent() {
        let _ops_guard = SERVICE_HANDLER_AVAILABILITY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];
        let (previous_ops, previous_state) =
            unsafe { install(manager.as_mut_ptr().cast(), 1, 0, 6, 1) };

        assert_eq!(unsafe { service_handler_is_available(1) }, 0);
        unsafe {
            assert_eq!(HANDLER_CALLS, 1, "handler access precedes the final AND");
            restore(previous_ops, 1, previous_state);
        }
    }

    #[test]
    fn reloads_the_global_gate_after_the_callees() {
        let _ops_guard = SERVICE_HANDLER_AVAILABILITY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = SERVICE_HANDLER_LIFECYCLE_RECORDS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut manager = [0u32; 16];
        let (previous_ops, previous_state) =
            unsafe { install(manager.as_mut_ptr().cast(), 1, 0x1000, 4, 0) };

        assert_eq!(unsafe { service_handler_is_available(1) }, 0);
        unsafe {
            assert_eq!(HANDLER_CALLS, 1);
            restore(previous_ops, 1, previous_state);
        }
    }
}
