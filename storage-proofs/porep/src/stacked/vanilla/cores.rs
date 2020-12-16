use log::*;
use std::sync::{Mutex, MutexGuard};

use anyhow::{bail, format_err, Result};
use hwloc2::{CpuBindFlags, ObjectType, Topology, TopologyObject};
use lazy_static::lazy_static;

use storage_proofs_core::settings;

type CoreGroup = Vec<CoreIndex>;
lazy_static! {
    pub static ref TOPOLOGY: Mutex<Option<Topology>> = Mutex::new(Topology::new());
    pub static ref CORE_GROUPS: Option<Vec<Mutex<CoreGroup>>> = {
        let settings = &settings::SETTINGS;
        let num_producers = settings.multicore_sdr_producers;
        let cores_per_unit = num_producers + 1;

        core_groups(cores_per_unit)
    };
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// `CoreIndex` is a simple wrapper type for indexes into the set of vixible cores. A `CoreIndex` should only ever be
/// created with a value known to be less than the number of visible cores.
pub struct CoreIndex(usize);

pub fn checkout_core_group() -> Option<MutexGuard<'static, CoreGroup>> {
    match &*CORE_GROUPS {
        Some(groups) => {
            for (i, group) in groups.iter().enumerate() {
                match group.try_lock() {
                    Ok(guard) => {
                        debug!("checked out core group {}", i);
                        return Some(guard);
                    }
                    Err(_) => debug!("core group {} locked, could not checkout", i),
                }
            }
            None
        }
        None => None,
    }
}

#[cfg(not(target_os = "windows"))]
pub type ThreadId = libc::pthread_t;

#[cfg(target_os = "windows")]
pub type ThreadId = winapi::winnt::HANDLE;

/// Helper method to get the thread id through libc, with current rust stable (1.5.0) its not
/// possible otherwise I think.
#[cfg(not(target_os = "windows"))]
fn get_thread_id() -> ThreadId {
    unsafe { libc::pthread_self() }
}

#[cfg(target_os = "windows")]
fn get_thread_id() -> ThreadId {
    unsafe { kernel32::GetCurrentThread() }
}

pub struct Cleanup {
    tid: ThreadId,
    prior_state: Option<hwloc2::Bitmap>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(prior) = self.prior_state.take() {
            if let Some(ref mut locked_topo) = &mut *TOPOLOGY.lock().expect("poisoned lock") {
                let _ = locked_topo.set_cpubind_for_thread(
                    self.tid,
                    prior,
                    CpuBindFlags::CPUBIND_THREAD,
                );
            }
        }
    }
}

pub fn bind_core(core_index: CoreIndex) -> Result<Cleanup> {
    let tid = get_thread_id();
    let mut guard = TOPOLOGY.lock().expect("poisoned lock");
    let locked_topo = match &mut *guard {
        Some(ref mut topo) => topo,
        None => bail!("no hwloc topology available"),
    };
    let core = get_core_by_index(&locked_topo, core_index)
        .map_err(|err| format_err!("failed to get core at index {}: {:?}", core_index.0, err))?;

    let cpuset = core
        .cpuset()
        .ok_or_else(|| format_err!("no allowed cpuset for core at index {}", core_index.0,))?;
    debug!("allowed cpuset: {:?}", cpuset);
    let mut bind_to = cpuset;

    // Get only one logical processor (in case the core is SMT/hyper-threaded).
    bind_to.singlify();

    // Thread binding before explicit set.
    let before = locked_topo.get_cpubind_for_thread(tid, CpuBindFlags::CPUBIND_THREAD);

    debug!("binding to {:?}", bind_to);
    // Set the binding.
    let result = locked_topo
        .set_cpubind_for_thread(tid, bind_to, CpuBindFlags::CPUBIND_THREAD)
        .map_err(|err| format_err!("failed to bind CPU: {:?}", err));

    if result.is_err() {
        warn!("error in bind_core, {:?}", result);
    }

    Ok(Cleanup {
        tid,
        prior_state: before,
    })
}

fn get_core_by_index<'a>(topo: &'a Topology, index: CoreIndex) -> Result<&'a TopologyObject> {
    let idx = index.0;

    match topo.objects_with_type(&ObjectType::Core) {
        Ok(all_cores) if idx < all_cores.len() => Ok(all_cores[idx]),
        Ok(all_cores) => Err(format_err!(
            "idx ({}) out of range for {} cores",
            idx,
            all_cores.len()
        )),
        _e => Err(format_err!("failed to get core by index {}", idx,)),
    }
}

fn core_groups(cores_per_unit: usize) -> Option<Vec<Mutex<Vec<CoreIndex>>>> {
    let mut guard = TOPOLOGY.lock().expect("poisoned lock");
    let topo = match &mut *guard {
        Some(ref mut topo) => topo,
        None => {
            warn!("no topology available");
            return None;
        }
    };

    let core_depth = match topo.depth_or_below_for_type(&ObjectType::Core) {
        Ok(depth) => depth,
        Err(err) => {
            warn!("failed to retrieve core depth: {:?}", err);
            return None;
        }
    };
    let all_cores = match topo.objects_with_type(&ObjectType::Core) {
        Ok(cores) => cores,
        Err(err) => {
            warn!("failed to retrieve cores: {:?}", err);
            return None;
        }
    };
    let core_count = all_cores.len();

    let mut cache_depth = core_depth;
    let mut cache_count = 0;

    while cache_depth > 0 {
        let objs = topo.objects_at_depth(cache_depth);
        let obj_count = objs.len();
        if obj_count < core_count {
            cache_count = obj_count;
            break;
        }

        cache_depth -= 1;
    }

    assert_eq!(0, core_count % cache_count);
    let mut group_size = core_count / cache_count;
    let mut group_count = cache_count;

    if cache_count <= 1 {
        // If there are not more than one shared caches, there is no benefit in trying to group cores by cache.
        // In that case, prefer more groups so we can still bind cores and also get some parallelism.
        // Create as many full groups as possible. The last group may not be full.
        group_count = core_count / cores_per_unit;
        group_size = cores_per_unit;

        info!(
            "found only {} shared cache(s), heuristically grouping cores into {} groups",
            cache_count, group_count
        );
    } else {
        debug!(
            "Cores: {}, Shared Caches: {}, cores per cache (group_size): {}",
            core_count, cache_count, group_size
        );
    }

    let core_groups = (0..group_count)
        .map(|i| {
            (0..group_size)
                .map(|j| {
                    let core_index = i * group_size + j;
                    assert!(core_index < core_count);
                    CoreIndex(core_index)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    Some(
        core_groups
            .iter()
            .map(|group| Mutex::new(group.clone()))
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cores() {
        core_groups(2);
    }

    #[test]
    #[cfg(feature = "single-threaded")]
    fn test_checkout_cores() {
        let checkout1 = checkout_core_group();
        dbg!(&checkout1);
        let checkout2 = checkout_core_group();
        dbg!(&checkout2);

        // This test might fail if run on a machine with fewer than four cores.
        match (checkout1, checkout2) {
            (Some(c1), Some(c2)) => assert!(*c1 != *c2),
            _ => panic!("failed to get two checkouts"),
        }
    }
}
