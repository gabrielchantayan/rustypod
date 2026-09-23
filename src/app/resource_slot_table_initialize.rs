//! `resource_slot_table_initialize` — original: `FUN_081b759c` @ 0x081b759c
//! (72 bytes, `0x081b759c..0x081b75e3`; the literal at `0x081b75e4` supplies
//! the table address, and the next real function begins at `0x081b75e8`).
//!
//! Raw decoding verifies one plain unconditional `bl` (`0x081b75c4`) and no
//! predicated `bl` forms; the function has three inbound plain `bl` calls and
//! no predicated inbound calls.
//!
//! Algorithm: initialize four 0x18-byte resource slots at state+0x88 from the
//! two four-word tables at 0x083eb2e0, then mark state+0xe9 initialized.
//!
//! Deliberate deviations: `FUN_081b7d2c` has no recovered semantic identity.
//! Target builds call its verified address; host tests replace only that call
//! with a narrow recording seam.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

/// ABI of the unidentified retail resource-slot initializer at 0x081b7d2c.
pub type ResourceSlotInitialize = unsafe extern "C" fn(*mut u8, *mut u8, u32, u32);

const RESOURCE_SLOT_COUNT: usize = 4;
const RESOURCE_SLOT_SIZE: usize = 0x18;
const RESOURCE_SLOT_OFFSET: usize = 0x88;
const RESOURCE_SLOTS_INITIALIZED_OFFSET: usize = 0xe9;

#[cfg(not(target_arch = "arm"))]
const HOST_RESOURCE_SLOT_TABLE: [u32; RESOURCE_SLOT_COUNT * 2] = [
    0xe131_0f84, 0x4a00_000b, 0xe112_000e, 0x11de_e001,
    0x0a00_0008, 0xe8bd_8070, 0xe1b0_5f84, 0x531e_0502,
];

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn resource_slot_table_word(index: usize) -> u32 {
    HOST_RESOURCE_SLOT_TABLE[index]
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_resource_slot_initialize(
    _state: *mut u8,
    _slot: *mut u8,
    _primary: u32,
    _secondary: u32,
) {
}

#[cfg(not(target_arch = "arm"))]
static mut RESOURCE_SLOT_INITIALIZE: ResourceSlotInitialize = missing_resource_slot_initialize;

#[cfg(not(target_arch = "arm"))]
#[inline(never)]
pub unsafe extern "C" fn resource_slot_table_initialize(state: *mut u8) {
    let initialize = unsafe { ptr::read_volatile(ptr::addr_of!(RESOURCE_SLOT_INITIALIZE)) };
    for index in 0..RESOURCE_SLOT_COUNT {
        let primary = resource_slot_table_word(index);
        let secondary = resource_slot_table_word(RESOURCE_SLOT_COUNT + index);
        let slot = unsafe { state.add(RESOURCE_SLOT_OFFSET + index * RESOURCE_SLOT_SIZE) };
        unsafe { initialize(state, slot, primary, secondary) };
    }
    unsafe { ptr::write_volatile(state.add(RESOURCE_SLOTS_INITIALIZED_OFFSET), 1) };
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .section .text.resource_slot_table_initialize,"ax",%progbits
    .global resource_slot_table_initialize
    .type resource_slot_table_initialize,%function
resource_slot_table_initialize:
    push {{r4,r5,r6,r7,r8,lr}}
    ldr r6, 1f
    mov r5, r0
    mov r4, #0
    add r7, r6, #16
0:
    add r0, r4, r4, lsl #1
    add r0, r5, r0, lsl #3
    add r1, r0, #136
    ldr r3, [r7, r4, lsl #2]
    ldr r2, [r6, r4, lsl #2]
    mov r0, r5
    ldr ip, 2f
    blx ip
    add r4, r4, #1
    cmp r4, #3
    ble 0b
    mov r0, #1
    strb r0, [r5, #233]
    pop {{r4,r5,r6,r7,r8,pc}}
1:  .word 0x083eb2e0
2:  .word 0x081b7d2c
"#);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static RESOURCE_SLOT_INITIALIZE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(*mut u8, *mut u8, u32, u32); RESOURCE_SLOT_COUNT] =
        [(ptr::null_mut(), ptr::null_mut(), 0, 0); RESOURCE_SLOT_COUNT];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_resource_slot_initialize(
        state: *mut u8,
        slot: *mut u8,
        primary: u32,
        secondary: u32,
    ) {
        unsafe {
            CALLS[CALL_COUNT] = (state, slot, primary, secondary);
            CALL_COUNT += 1;
        }
    }

    #[test]
    fn initializes_all_slots_before_marking_state() {
        let _lock = RESOURCE_SLOT_INITIALIZE_TEST_LOCK.lock();
        let mut state = [0u8; RESOURCE_SLOTS_INITIALIZED_OFFSET + 1];
        unsafe {
            CALL_COUNT = 0;
            RESOURCE_SLOT_INITIALIZE = record_resource_slot_initialize;
            resource_slot_table_initialize(state.as_mut_ptr());

            assert_eq!(CALL_COUNT, RESOURCE_SLOT_COUNT);
            assert_eq!(state[RESOURCE_SLOTS_INITIALIZED_OFFSET], 1);
            for index in 0..RESOURCE_SLOT_COUNT {
                let (seen_state, slot, primary, secondary) = CALLS[index];
                assert_eq!(seen_state, state.as_mut_ptr());
                assert_eq!(slot, state.as_mut_ptr().add(RESOURCE_SLOT_OFFSET + index * RESOURCE_SLOT_SIZE));
                assert_eq!(primary, resource_slot_table_word(index));
                assert_eq!(secondary, resource_slot_table_word(RESOURCE_SLOT_COUNT + index));
            }
            RESOURCE_SLOT_INITIALIZE = missing_resource_slot_initialize;
        }
    }
}
