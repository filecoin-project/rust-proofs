use std::cell::UnsafeCell;
use std::fs::File;
use std::hint::spin_loop;
use std::marker::{PhantomData, Sync};
use std::mem::size_of;
use std::path::Path;
use std::slice;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use anyhow::Result;
use byte_slice_cast::{AsSliceOf, FromByteSlice};
use log::{info, warn};
use mapr::{Mmap, MmapMut, MmapOptions};

use storage_proofs_core::api_version::ApiVersion;

pub struct CacheReader<T> {
    file: File,
    bufs: UnsafeCell<[Mmap; 2]>,
    size: usize,
    degree: usize,
    window_size: usize,
    cursor: IncrementingCursor,
    consumer: AtomicU64,
    api_version: ApiVersion,
    _t: PhantomData<T>,
}

unsafe impl<T> Sync for CacheReader<T> {}

struct IncrementingCursor {
    cur: AtomicUsize,
    cur_safe: AtomicUsize,
}

fn compare_and_swap(atomic: &AtomicUsize, before: usize, after: usize) -> usize {
    match atomic.compare_exchange_weak(before, after, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(x) => {
            assert_eq!(x, before);
            before
        }
        _ => after,
    }
}

/// IncrementingCursor provides an atomic variable which can be incremented such that only one thread attempting the
/// increment is selected to perform actions required to effect the transition. Unselected threads wait until the
/// transition has completed. Transition and wait condition are both specified by closures supplied by the caller.
impl IncrementingCursor {
    fn new(val: usize) -> Self {
        Self {
            cur: AtomicUsize::new(val),
            cur_safe: AtomicUsize::new(val),
        }
    }

    fn store(&self, val: usize) {
        self.cur.store(val, Ordering::SeqCst);
        self.cur_safe.store(val, Ordering::SeqCst);
    }

    fn compare_and_swap(&self, before: usize, after: usize) {
        compare_and_swap(&self.cur, before, after);
        compare_and_swap(&self.cur_safe, before, after);
    }

    fn increment<F: Fn() -> bool, G: Fn()>(&self, target: usize, wait_fn: F, advance_fn: G) {
        // Check using `cur_safe`, to ensure we wait until the current cursor value is safe to use.
        // If we were to instead check `cur`, it could have been incremented but not yet safe.
        let cur = self.cur_safe.load(Ordering::SeqCst);
        if target > cur {
            // Only one producer will successfully increment `cur`. We need this second atomic because we cannot
            // increment `cur_safe` until after the underlying resource has been advanced.
            let instant_cur = compare_and_swap(&self.cur, cur, cur + 1);
            if instant_cur == cur {
                // We successfully incremented `self.cur`, so we are responsible for advancing the resource.
                {
                    while wait_fn() {
                        spin_loop()
                    }
                }

                advance_fn();

                // Now it is safe to use the new window.
                self.cur_safe.fetch_add(1, Ordering::SeqCst);
            } else {
                // We failed to increment `self.cur_window`, so we must wait for the window to be advanced before
                // continuing. Wait until it is safe to use the new current window.
                while self.cur_safe.load(Ordering::SeqCst) != cur + 1 {
                    spin_loop()
                }
            }
        }
    }
}

impl<T: FromByteSlice> CacheReader<T> {
    pub fn new(
        filename: &Path,
        window_size: Option<usize>,
        degree: usize,
        api_version: ApiVersion,
    ) -> Result<Self> {
        info!("initializing cache");
        let file = File::open(filename)?;
        let size = File::metadata(&file)?.len() as usize;
        let window_size = match window_size {
            Some(s) => {
                if s < size {
                    assert_eq!(
                        0,
                        size % degree * size_of::<T>(),
                        "window size is not multiple of element size"
                    );
                };
                s
            }
            None => {
                let num_windows = 8;
                assert_eq!(0, size % num_windows);
                size / num_windows
            }
        };

        let buf0 = Self::map_buf(0, window_size, &file)?;
        let buf1 = Self::map_buf(window_size as u64, window_size, &file)?;
        Ok(Self {
            file,
            bufs: UnsafeCell::new([buf0, buf1]),
            size,
            degree,
            window_size,
            // The furthest window from which the cache has yet been read.
            cursor: IncrementingCursor::new(0),
            consumer: AtomicU64::new(0),
            api_version,
            _t: PhantomData::<T>,
        })
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn window_nodes(&self) -> usize {
        self.size() / (size_of::<T>() * self.degree)
    }

    /// Safety: incrementing the consumer at the end of a window will unblock the producer waiting to remap the
    /// consumer's previous buffer. The buffer must not be accessed once this has happened.
    pub unsafe fn increment_consumer(&self) {
        self.consumer.fetch_add(1, Ordering::SeqCst);
    }

    pub fn store_consumer(&self, val: u64) {
        self.consumer.store(val, Ordering::SeqCst);
    }

    pub fn get_consumer(&self) -> u64 {
        self.consumer.load(Ordering::SeqCst)
    }

    #[inline]
    fn get_bufs(&self) -> &[Mmap] {
        unsafe { &std::slice::from_raw_parts((*self.bufs.get()).as_ptr(), 2) }
    }

    #[inline]
    #[allow(clippy::mut_from_ref)]
    unsafe fn get_mut_bufs(&self) -> &mut [Mmap] {
        slice::from_raw_parts_mut((*self.bufs.get()).as_mut_ptr(), 2)
    }

    #[allow(dead_code)]
    // This is unused, but included to document the meaning of its components.
    // This allows splitting the reset in order to avoid a pause.
    pub fn reset(&self) -> Result<()> {
        self.start_reset()?;
        self.finish_reset()
    }

    pub fn start_reset(&self) -> Result<()> {
        let buf0 = Self::map_buf(0, self.window_size, &self.file)?;
        let bufs = unsafe { self.get_mut_bufs() };
        bufs[0] = buf0;
        Ok(())
    }

    pub fn finish_reset(&self) -> Result<()> {
        let buf1 = Self::map_buf(self.window_size as u64, self.window_size, &self.file)?;
        let bufs = unsafe { self.get_mut_bufs() };
        bufs[1] = buf1;
        self.cursor.store(0);
        Ok(())
    }

    pub fn api_version(&self) -> ApiVersion {
        self.api_version
    }

    fn map_buf(offset: u64, len: usize, file: &File) -> Result<Mmap> {
        unsafe {
            MmapOptions::new()
                .offset(offset)
                .len(len)
                .private()
                .map(file)
                .map_err(|e| e.into())
        }
    }

    #[inline]
    fn window_element_count(&self) -> usize {
        self.window_size / size_of::<T>()
    }

    /// `pos` is in units of `T`.
    #[inline]
    /// Safety: A returned slice must not be accessed once the buffer from which it has been derived is remapped. A
    /// buffer will never be remapped until the `consumer` atomic contained in `self` has been advanced past the end of
    /// the window. NOTE: each time `consumer` is incremented, `self.degrees` elements of the cache are invalidated.
    /// This means callers should only access slice elements sequentially. They should only call `increment_consumer`
    /// once the next `self.degree` elements of the cache will never be accessed again.
    pub unsafe fn consumer_slice_at(&self, pos: usize) -> &[T] {
        assert!(
            pos < self.size,
            "pos {} out of range for buffer of size {}",
            pos,
            self.size
        );
        let window = pos / self.window_element_count();
        let pos = pos % self.window_element_count();
        let targeted_buf = &self.get_bufs()[window % 2];

        &targeted_buf.as_slice_of::<T>().expect("as_slice_of failed")[pos..]
    }

    /// `pos` is in units of `T`.
    #[inline]
    /// Safety: This call may advance the rear buffer, making it unsafe to access slices derived from that buffer again.
    /// It is the callers responsibility to ensure such illegal access is not attempted. This can be prevented if users
    /// never access values past which the cache's `consumer` atomic has been incremented. NOTE: each time `consumer` is
    /// incremented, `self.degrees` elements of the cache are invalidated.
    pub unsafe fn slice_at(&self, pos: usize) -> &[T] {
        assert!(
            pos < self.size,
            "pos {} out of range for buffer of size {}",
            pos,
            self.size
        );
        let window = pos / self.window_element_count();
        if window == 1 {
            self.cursor.compare_and_swap(0, 1);
        }

        let pos = pos % self.window_element_count();

        let wait_fn = || {
            let safe_consumer = (window - 1) * (self.window_element_count() / self.degree);
            (self.consumer.load(Ordering::SeqCst) as usize) < safe_consumer
        };

        self.cursor
            .increment(window, &wait_fn, &|| self.advance_rear_window(window));

        let targeted_buf = &self.get_bufs()[window % 2];

        &targeted_buf.as_slice_of::<T>().expect("as_slice_of failed")[pos..]
    }

    fn advance_rear_window(&self, new_window: usize) {
        assert!(new_window as usize * self.window_size < self.size);

        let replace_idx = (new_window % 2) as usize;

        let new_buf = Self::map_buf(
            (new_window * self.window_size) as u64,
            self.window_size as usize,
            &self.file,
        )
        .expect("map_buf failed");

        unsafe {
            self.get_mut_bufs()[replace_idx] = new_buf;
        }
    }
}

fn allocate_layer(sector_size: usize) -> Result<MmapMut> {
    match MmapOptions::new()
        .len(sector_size)
        .private()
        .clone()
        .lock()
        .map_anon()
        .and_then(|mut layer| {
            layer.mlock()?;
            Ok(layer)
        }) {
        Ok(layer) => Ok(layer),
        Err(err) => {
            // fallback to not locked if permissions are not available
            warn!("failed to lock map {:?}, falling back", err);
            let layer = MmapOptions::new().len(sector_size).private().map_anon()?;
            Ok(layer)
        }
    }
}

pub fn setup_create_label_memory(
    sector_size: usize,
    degree: usize,
    window_size: Option<usize>,
    cache_path: &Path,
    api_version: ApiVersion,
) -> Result<(CacheReader<u32>, MmapMut, MmapMut)> {
    let parents_cache = CacheReader::new(cache_path, window_size, degree, api_version)?;
    let layer_labels = allocate_layer(sector_size)?;
    let exp_labels = allocate_layer(sector_size)?;

    Ok((parents_cache, layer_labels, exp_labels))
}
