use std::cell::UnsafeCell;
use std::slice::{self, ChunksExactMut};

/// A slice type which can be shared between threads, but must be fully managed by the caller.
/// Any synchronization must be ensured by the caller, which is why all access is `unsafe`.
#[derive(Debug)]
pub struct UnsafeSlice<'a, T> {
    // holds the data to ensure lifetime correctness
    data: UnsafeCell<&'a mut [T]>,
    /// pointer to the data
    ptr: *mut T,
    /// Number of elements, not bytes.
    len: usize,
}

unsafe impl<'a, T> Sync for UnsafeSlice<'a, T> {}

impl<'a, T> UnsafeSlice<'a, T> {
    /// Takes mutable slice, to ensure that `UnsafeSlice` is the only user of this memory, until it gets dropped.
    pub fn from_slice(source: &'a mut [T]) -> Self {
        let len = source.len();
        let ptr = source.as_mut_ptr();
        let data = UnsafeCell::new(source);
        Self { data, ptr, len }
    }

    /// Safety: The caller must ensure that there are no unsynchronized parallel access to the same regions.
    #[inline]
    pub unsafe fn as_mut_slice(&self) -> &'a mut [T] {
        slice::from_raw_parts_mut(self.ptr, self.len)
    }
    /// Safety: The caller must ensure that there are no unsynchronized parallel access to the same regions.
    #[inline]
    pub unsafe fn as_slice(&self) -> &'a [T] {
        slice::from_raw_parts(self.ptr, self.len)
    }

    #[inline]
    pub unsafe fn get_mut(&self, index: usize) -> &'a mut T {
        &mut *self.ptr.add(index)
    }
}

/// Set all values in the given slice to the provided value.
#[inline]
pub fn memset(slice: &mut [u8], value: u8) {
    for v in slice.iter_mut() {
        *v = value;
    }
}

#[inline]
pub fn prepare_block(replica_id: &[u8], layer: u32, buf: &mut [u8]) {
    buf[..32].copy_from_slice(replica_id);
    buf[35] = (layer & 0xFF) as u8;
    buf[64] = 0x80; // Padding
    buf[126] = 0x02 // Length (512 bits = 64B)
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitMask(u32);

impl BitMask {
    /// Sets the full mask for the first `n` bits.
    #[inline]
    pub fn set_upto(&mut self, n: u8) {
        assert!(n <= 32);
        self.0 |= (1 << n) - 1
    }

    /// Sets the ith bit.
    #[inline]
    pub fn set(&mut self, i: usize) {
        self.0 |= 1 << i
    }

    /// Returns true if the ith bit is set, false otherwise.
    #[inline]
    pub fn get(self, i: usize) -> bool {
        self.0 & (1 << i) != 0
    }
}

#[derive(Debug)]
pub struct RingBuf {
    data: UnsafeCell<Box<[u8]>>,
    slot_size: usize,
    num_slots: usize,
}

unsafe impl Sync for RingBuf {}

impl RingBuf {
    /// Creates a new
    pub fn new(slot_size: usize, num_slots: usize) -> Self {
        let data = vec![0u8; slot_size * num_slots].into_boxed_slice();

        RingBuf {
            data: UnsafeCell::from(data),
            slot_size,
            num_slots,
        }
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn slice_mut(&self) -> &mut [u8] {
        slice::from_raw_parts_mut((*self.data.get()).as_mut_ptr(), self.len())
    }

    fn len(&self) -> usize {
        self.slot_size * self.num_slots
    }

    #[allow(clippy::mut_from_ref)]
    pub unsafe fn slot_mut(&self, slot: usize) -> &mut [u8] {
        let start = self.slot_size * slot;
        let end = start + self.slot_size;

        &mut self.slice_mut()[start..end]
    }

    pub fn iter_slot_mut(&mut self) -> ChunksExactMut<'_, u8> {
        // Safety: safe because we are holding &mut self
        unsafe { self.slice_mut().chunks_exact_mut(self.slot_size) }
    }
}
