/// vector8_erase — original: `FUN_083e6ffc` @ 0x083e6ffc (76 bytes).
///
/// Erases the eight-byte element at `position` from a three-word C++ vector
/// head. If the vector is nonempty, it shifts each following pair of target
/// words one slot toward the beginning, decrements `end` by eight bytes, and
/// returns the original position. The element has a trivial destructor.
///
/// Raw decoding establishes the exact extent: 19 ARM words from `push {r4,lr}`
/// through `pop {r4,pc}`, followed by `FUN_083e7048` at 0x083e7048. It makes
/// no outbound BL calls. A whole-image scan finds three inbound direct calls,
/// all unconditional plain `bl` at 0x0826a1b8, 0x0826a274, and 0x082caa84;
/// there are no predicated BL calls. Deliberate deviations: none.
///
/// # Safety
///
/// `vector` must address three readable target-width words containing begin,
/// end, and capacity. For a nonempty vector, `position` and every eight-byte
/// element through end must be readable and writable. As in retailOS,
/// `position` is assumed to designate an element of the vector.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector8_erase(vector: *mut u32, position: *mut u32) -> *mut u32 {
    let end = unsafe { vector.add(1).read() as *mut u32 };
    if unsafe { vector.read() as *mut u32 } != end {
        let mut source = unsafe { position.add(2) };
        let mut destination = position;
        while source != end {
            unsafe {
                destination.write(source.read());
                destination.add(1).write(source.add(1).read());
            }
            destination = unsafe { destination.add(2) };
            source = unsafe { source.add(2) };
        }
        unsafe { vector.add(1).write(end.sub(2) as usize as u32) };
    }
    position
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    const FIXTURE_LEN: usize = 0x1000;
    const ELEMENTS_OFFSET: usize = 0x100;

    fn fixture() -> Option<*mut u32> {
        let base = try_map_u32_slab(hints::VECTOR8_ERASE, FIXTURE_LEN)?;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        Some(unsafe { base.add(ELEMENTS_OFFSET).cast() })
    }

    #[test]
    fn shifts_following_pairs_and_returns_erased_position() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(elements) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/vector8_erase"));
            return;
        };
        unsafe {
            elements.add(0).write(10);
            elements.add(1).write(11);
            elements.add(2).write(20);
            elements.add(3).write(21);
            elements.add(4).write(30);
            elements.add(5).write(31);
            let mut vector = [elements as usize as u32, elements.add(6) as usize as u32, 0];
            let result = vector8_erase(vector.as_mut_ptr(), elements.add(2));
            assert_eq!(result, elements.add(2));
            assert_eq!([elements.read(), elements.add(1).read(), elements.add(2).read(), elements.add(3).read()], [10, 11, 30, 31]);
            assert_eq!(vector[1], elements.add(4) as usize as u32);
        }
    }

    #[test]
    fn erasing_last_element_only_reduces_end() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(elements) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/vector8_erase"));
            return;
        };
        unsafe {
            elements.write(40);
            elements.add(1).write(41);
            let mut vector = [elements as usize as u32, elements.add(2) as usize as u32, 0];
            assert_eq!(vector8_erase(vector.as_mut_ptr(), elements), elements);
            assert_eq!([elements.read(), elements.add(1).read()], [40, 41]);
            assert_eq!(vector[1], elements as usize as u32);
        }
    }

    #[test]
    fn empty_vector_leaves_end_unchanged() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(elements) = fixture() else {
            assert!(note_missing_u32_fixture("cxx/vector8_erase"));
            return;
        };
        unsafe {
            let mut vector = [elements as usize as u32; 3];
            assert_eq!(vector8_erase(vector.as_mut_ptr(), elements), elements);
            assert_eq!(vector[1], elements as usize as u32);
        }
    }
}
