//! Four-slot key lookup — original: `FUN_08293048` @ `0x08293048`
//! (48 bytes: 44 bytes of code plus a 4-byte table-address literal).
//!
//! Raw ARM, bounded by the following body at `0x08293078`, is:
//!
//! ```text
//! ldr r2,[pc,#0x24]     ; 0x089d04c4
//! mov r0,#0
//! loop: add r3,r0,r0,lsl#1
//!       ldrb r3,[r2,r3,lsl#3]
//!       cmp r3,r1
//!       bxeq lr
//!       add r0,r0,#1
//!       cmp r0,#4
//!       blt loop
//! mvn r0,#0
//! bx lr
//! ```
//!
//! A binary scan of every ARM `B`/`BL` word in `osos.dec` finds ten direct
//! call sites, all unconditional `bl`; there are no predicated calls or tail
//! branches. The first ABI argument is killed by `mov r0,#0` and is retained
//! only because every retail caller supplies it.
//!
//! The function searches the key byte at offset zero of each of the four
//! 24-byte records in the runtime table at `0x089d04c4`, returning the first
//! matching record index or `-1`. `cmp r3,r1` compares the zero-extended byte
//! against the whole `u32` key, so keys above `0xff` cannot match.
//!
//! Deliberate deviation: target builds read the firmware's runtime table;
//! host builds use equivalent private storage so tests can exercise the
//! lookup without mapping retail RAM. The volatile read preserves the target
//! table's runtime-mutability across calls.

const SLOT_COUNT: usize = 4;
const SLOT_SIZE: usize = 0x18;
const SLOT_KEY_TABLE_ADDRESS: usize = 0x089d_04c4;

#[cfg(target_os = "none")]
fn slot_key_table() -> *const u8 {
    SLOT_KEY_TABLE_ADDRESS as *const u8
}

#[cfg(not(target_os = "none"))]
static mut HOST_SLOT_KEY_TABLE: [u8; SLOT_COUNT * SLOT_SIZE] = [0; SLOT_COUNT * SLOT_SIZE];

#[cfg(not(target_os = "none"))]
fn slot_key_table() -> *const u8 {
    core::ptr::addr_of!(HOST_SLOT_KEY_TABLE).cast::<u8>()
}
/// `four_slot_key_index` — original: `FUN_08293048` @ `0x08293048`
/// (48 bytes: 44 bytes of code plus its literal; 10 direct unconditional
/// `bl` call sites, binary-scanned).
///
/// Returns the index of the first four-slot-table record whose leading key
/// byte equals `key`, or `-1` when none matches. `context` is intentionally
/// unused, matching the retail `mov r0,#0` before the loop.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn four_slot_key_index(_context: *mut u8, key: u32) -> i32 {
    let table = slot_key_table();

    for index in 0..SLOT_COUNT {
        let record_key = unsafe { table.add(index * SLOT_SIZE).read_volatile() };
        if record_key as u32 == key {
            return index as i32;
        }
    }

    -1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;

    use super::{four_slot_key_index, HOST_SLOT_KEY_TABLE, SLOT_COUNT, SLOT_SIZE};

    fn set_slot_key(index: usize, key: u8) {
        unsafe {
            core::ptr::addr_of_mut!(HOST_SLOT_KEY_TABLE)
                .cast::<u8>()
                .add(index * SLOT_SIZE)
                .write(key);
        }
    }

    #[test]
    fn returns_first_matching_index_and_rejects_missing_full_width_keys() {
        unsafe {
            core::ptr::addr_of_mut!(HOST_SLOT_KEY_TABLE)
                .cast::<u8>()
                .write_bytes(0, SLOT_COUNT * SLOT_SIZE);
        }
        set_slot_key(0, 0x11);
        set_slot_key(1, 0x77);
        set_slot_key(2, 0x77);
        set_slot_key(3, 0xfe);

        assert_eq!(four_slot_key_index(ptr::null_mut(), 0x11), 0);
        assert_eq!(four_slot_key_index(ptr::null_mut(), 0x77), 1, "first duplicate wins");
        assert_eq!(four_slot_key_index(ptr::null_mut(), 0xfe), 3, "final record is searched");
        assert_eq!(four_slot_key_index(ptr::null_mut(), 0), -1);
        assert_eq!(four_slot_key_index(ptr::null_mut(), 0x0000_0177), -1,
                   "a byte key is compared against the full second-register value");
    }
}
