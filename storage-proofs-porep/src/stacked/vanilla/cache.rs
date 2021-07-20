use std::collections::BTreeMap;
use std::fs::{remove_file, File};
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use byteorder::{ByteOrder, LittleEndian};
use filecoin_hashers::Hasher;
use lazy_static::lazy_static;
use log::{info, trace};
use mapr::{Mmap, MmapOptions};
use rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    api_version::ApiVersion,
    drgraph::{Graph, BASE_DEGREE},
    error::Result,
    parameter_cache::{with_exclusive_lock, LockedFile, ParameterSetMetadata, VERSION},
    settings::SETTINGS,
    util::NODE_SIZE,
};

use crate::stacked::vanilla::graph::{StackedGraph, DEGREE};

/// u32 = 4 bytes
const NODE_BYTES: usize = 4;

pub const PARENT_CACHE_DATA: &str = include_str!("../../../parent_cache.json");

pub type ParentCacheDataMap = BTreeMap<String, ParentCacheData>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ParentCacheData {
    pub digest: String,
    pub sector_size: u64,
}

lazy_static! {
    pub static ref PARENT_CACHE: ParentCacheDataMap =
        serde_json::from_str(PARENT_CACHE_DATA).expect("Invalid parent_cache.json");
}

// StackedGraph will hold two different (but related) `ParentCache`,
#[derive(Debug)]
pub struct ParentCache {
    /// Disk path for the cache.
    pub path: PathBuf,
    /// The total number of cache entries.
    num_cache_entries: u32,
    cache: CacheData,
    pub sector_size: usize,
    pub digest: String,
    pub api_version: ApiVersion,
}

#[derive(Debug)]
struct CacheData {
    /// This is a large list of fixed (parent) sized arrays.
    data: Mmap,
    /// Offset in nodes.
    offset: u32,
    /// Len in nodes.
    len: u32,
    /// The underlyling file.
    file: LockedFile,
}

impl CacheData {
    /// Change the cache to point to the newly passed in offset.
    ///
    /// The `new_offset` must be set, such that `new_offset + len` does not
    /// overflow the underlying data.
    fn shift(&mut self, new_offset: u32) -> Result<()> {
        if self.offset == new_offset {
            return Ok(());
        }

        let offset = new_offset as usize * DEGREE * NODE_BYTES;
        let len = self.len as usize * DEGREE * NODE_BYTES;

        self.data = unsafe {
            MmapOptions::new()
                .offset(offset as u64)
                .len(len)
                .map(self.file.as_ref())
                .context("could not shift mmap}")?
        };
        self.offset = new_offset;

        Ok(())
    }

    /// Returns true if this node is in the cached range.
    fn contains(&self, node: u32) -> bool {
        node >= self.offset && node < self.offset + self.len
    }

    /// Read the parents for the given node from cache.
    ///
    /// Panics if the `node` is not in the cache.
    fn read(&self, node: u32) -> [u32; DEGREE] {
        assert!(node >= self.offset, "node not in cache");
        let start = (node - self.offset) as usize * DEGREE * NODE_BYTES;
        let end = start + DEGREE * NODE_BYTES;

        let mut res = [0u32; DEGREE];
        LittleEndian::read_u32_into(&self.data[start..end], &mut res);
        res
    }

    fn reset(&mut self) -> Result<()> {
        if self.offset == 0 {
            return Ok(());
        }

        self.shift(0)
    }

    fn open(offset: u32, len: u32, path: &Path) -> Result<Self> {
        let min_cache_size = (offset + len) as usize * DEGREE * NODE_BYTES;

        let file = LockedFile::open_shared_read(path)
            .with_context(|| format!("could not open path={}", path.display()))?;

        let actual_len = file.as_ref().metadata()?.len();
        if actual_len < min_cache_size as u64 {
            bail!(
                "corrupted cache: {}, expected at least {}, got {} bytes",
                path.display(),
                min_cache_size,
                actual_len
            );
        }

        let data = unsafe {
            MmapOptions::new()
                .offset((offset as usize * DEGREE * NODE_BYTES) as u64)
                .len(len as usize * DEGREE * NODE_BYTES)
                .map(file.as_ref())
                .with_context(|| format!("could not mmap path={}", path.display()))?
        };

        Ok(Self {
            data,
            file,
            len,
            offset,
        })
    }
}

impl ParentCache {
    pub fn new<H, G>(len: u32, cache_entries: u32, graph: &StackedGraph<H, G>) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        let path = cache_path(cache_entries, graph);
        if path.exists() {
            Self::open(len, cache_entries, graph, &path)
        } else {
            match Self::generate(len, cache_entries, graph, &path) {
                Ok(c) => Ok(c),
                Err(err) => {
                    match err.downcast::<io::Error>() {
                        Ok(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            // cache was written from another process, just read it
                            Self::open(len, cache_entries, graph, &path)
                        }
                        Ok(error) => Err(error.into()),
                        Err(error) => Err(error),
                    }
                }
            }
        }
    }

    /// Opens an existing cache from disk.  If the verify_cache option
    /// is enabled, we rehash the data and compare with the persisted
    /// hash file.  If the persisted hash file does not exist, we
    /// re-generate the cache file, which will create it.
    pub fn open<H, G>(
        len: u32,
        cache_entries: u32,
        graph: &StackedGraph<H, G>,
        path: &Path,
    ) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        // Check if current entry is part of the official parent cache manifest.  If not, we're
        // dealing with some kind of test sector.  If verify has been requested but it's not a
        // production entry in the manifest, we'll calculate the digest so that it can be returned,
        // although we don't attempt to match it up to anything.  This is useful for the case of
        // generating new additions to the parent cache manifest since a valid digest is required.
        let (parent_cache_data, verify_cache, is_production, mut digest_hex) =
            match get_parent_cache_data(&path) {
                None => {
                    info!("[open] Parent cache data is not supported in production");

                    (
                        None,
                        SETTINGS.verify_cache,
                        false, // not production since not in manifest
                        "".to_string(),
                    )
                }
                Some(pcd) => (
                    Some(pcd),
                    SETTINGS.verify_cache,
                    true, // is_production since it exists in the manifest
                    pcd.digest.clone(),
                ),
            };

        info!(
            "parent cache: opening {}, verify enabled: {}",
            path.display(),
            verify_cache
        );

        if verify_cache {
            // Always check all of the data for integrity checks, even
            // if we're only opening a portion of it.
            let mut hasher = Sha256::new();
            info!("[open] parent cache: calculating consistency digest");
            let file = File::open(&path)?;
            let data = unsafe {
                MmapOptions::new()
                    .map(&file)
                    .with_context(|| format!("could not mmap path={}", path.display()))?
            };
            hasher.update(&data);
            drop(data);

            let hash = hasher.finalize();
            digest_hex = hash.iter().map(|x| format!("{:01$x}", x, 2)).collect();

            info!(
                "[open] parent cache: calculated consistency digest: {:?}",
                digest_hex
            );

            if is_production {
                let parent_cache_data = parent_cache_data.expect("parent_cache_data failure");

                trace!(
                    "[{}] Comparing {:?} to {:?}",
                    graph.size() * NODE_SIZE,
                    digest_hex,
                    parent_cache_data.digest
                );

                if digest_hex == parent_cache_data.digest {
                    info!("[open] parent cache: cache is verified!");
                } else {
                    info!(
                        "[!!!] Parent cache digest mismatch detected.  Regenerating {}",
                        path.display()
                    );
                    // delete invalid cache
                    remove_file(path)?;
                    ensure!(
                        Self::generate(len, graph.size() as u32, graph, path).is_ok(),
                        "Failed to generate parent cache"
                    );

                    // Note that if we wanted the user to manually terminate after repeated
                    // generation attemps, we could recursively return Self::open(...) here.
                }
            }
        }

        Ok(ParentCache {
            cache: CacheData::open(0, len, &path)?,
            path: path.to_path_buf(),
            num_cache_entries: cache_entries,
            sector_size: graph.size() * NODE_SIZE,
            digest: digest_hex,
            api_version: graph.api_version(),
        })
    }

    /// Generates a new cache and stores it on disk.
    pub fn generate<H, G>(
        len: u32,
        cache_entries: u32,
        graph: &StackedGraph<H, G>,
        path: &Path,
    ) -> Result<Self>
    where
        H: Hasher,
        G: Graph<H> + ParameterSetMetadata + Send + Sync,
    {
        info!("parent cache: generating {}", path.display());
        let mut digest_hex: String = "".to_string();
        let sector_size = graph.size() * NODE_SIZE;

        with_exclusive_lock(&path.to_path_buf(), |file| {
            let cache_size = cache_entries as usize * NODE_BYTES * DEGREE;
            file.as_ref()
                .set_len(cache_size as u64)
                .with_context(|| format!("failed to set length: {}", cache_size))?;

            let mut data = unsafe {
                MmapOptions::new()
                    .map_mut(file.as_ref())
                    .with_context(|| format!("could not mmap path={}", path.display()))?
            };

            data.par_chunks_mut(DEGREE * NODE_BYTES)
                .enumerate()
                .try_for_each(|(node, entry)| -> Result<()> {
                    let mut parents = [0u32; DEGREE];
                    graph
                        .base_graph()
                        .parents(node, &mut parents[..BASE_DEGREE])?;
                    graph.generate_expanded_parents(node, &mut parents[BASE_DEGREE..]);

                    LittleEndian::write_u32_into(&parents, entry);
                    Ok(())
                })?;

            info!("parent cache: generated");
            data.flush().context("failed to flush parent cache")?;

            info!("[generate] parent cache: generating consistency digest");
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();
            digest_hex = hash.iter().map(|x| format!("{:01$x}", x, 2)).collect();
            info!(
                "[generate] parent cache: generated consistency digest: {:?}",
                digest_hex
            );

            // Check if current entry is part of the official manifest and verify
            // that what we just generated matches what we expect for this entry
            // (if found). If not, we're dealing with some kind of test sector.
            match get_parent_cache_data(&path) {
                None => {
                    info!("[generate] Parent cache data is not supported in production");
                }
                Some(pcd) => {
                    ensure!(
                        digest_hex == pcd.digest,
                        "Newly generated parent cache is invalid"
                    );
                }
            };

            drop(data);

            info!("parent cache: written to disk");
            Ok(())
        })?;

        Ok(ParentCache {
            cache: CacheData::open(0, len, &path)?,
            path: path.to_path_buf(),
            num_cache_entries: cache_entries,
            sector_size,
            digest: digest_hex,
            api_version: graph.api_version(),
        })
    }

    /// Read a single cache element at position `node`.
    pub fn read(&mut self, node: u32) -> Result<[u32; DEGREE]> {
        if self.cache.contains(node) {
            return Ok(self.cache.read(node));
        }

        // not in memory, shift cache
        ensure!(
            node >= self.cache.offset + self.cache.len,
            "cache must be read in ascending order {} < {} + {}",
            node,
            self.cache.offset,
            self.cache.len,
        );

        // Shift cache by its current size.
        let new_offset =
            (self.num_cache_entries - self.cache.len).min(self.cache.offset + self.cache.len);
        self.cache.shift(new_offset)?;

        Ok(self.cache.read(node))
    }

    /// Resets the partial cache to the beginning.
    pub fn reset(&mut self) -> Result<()> {
        self.cache.reset()
    }
}

fn parent_cache_dir_name() -> String {
    SETTINGS.parent_cache.clone()
}

fn parent_cache_id(path: &Path) -> String {
    Path::new(&path)
        .file_stem()
        .expect("parent_cache_id file_stem failure")
        .to_str()
        .expect("parent_cache_id to_str failure")
        .to_string()
}

/// Get the correct parent cache data for a given cache id.
fn get_parent_cache_data(path: &Path) -> Option<&ParentCacheData> {
    PARENT_CACHE.get(&parent_cache_id(path))
}

fn cache_path<H, G>(cache_entries: u32, graph: &StackedGraph<H, G>) -> PathBuf
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Send + Sync,
{
    let mut hasher = Sha256::default();

    hasher.update(H::name());
    hasher.update(graph.identifier());
    for key in &graph.feistel_keys {
        hasher.update(key.to_le_bytes());
    }
    hasher.update(cache_entries.to_le_bytes());
    let h = hasher.finalize();
    PathBuf::from(parent_cache_dir_name()).join(format!(
        "v{}-sdr-parent-{}.cache",
        VERSION,
        hex::encode(h),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::poseidon::PoseidonHasher;
    use storage_proofs_core::api_version::ApiVersion;

    use crate::stacked::vanilla::graph::{StackedBucketGraph, EXP_DEGREE};

    #[test]
    fn test_read_full_range() {
        let nodes = 24u32;
        let graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(
            nodes as usize,
            BASE_DEGREE,
            EXP_DEGREE,
            [0u8; 32],
            ApiVersion::V1_0_0,
        )
        .expect("new_stacked failure");

        let mut cache = ParentCache::new(nodes, nodes, &graph).expect("parent cache new failure");

        for node in 0..nodes {
            let mut expected_parents = [0; DEGREE];
            graph
                .parents(node as usize, &mut expected_parents)
                .expect("graph parents failure");
            let parents = cache.read(node).expect("cache read failure");

            assert_eq!(expected_parents, parents);
        }
    }

    #[test]
    fn test_read_partial_range() {
        let nodes = 48u32;
        let graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(
            nodes as usize,
            BASE_DEGREE,
            EXP_DEGREE,
            [0u8; 32],
            ApiVersion::V1_0_0,
        )
        .expect("new_stacked failure");

        let mut half_cache =
            ParentCache::new(nodes / 2, nodes, &graph).expect("parent cache new failure");
        let mut quarter_cache =
            ParentCache::new(nodes / 4, nodes, &graph).expect("parent cache new failure");

        for node in 0..nodes {
            let mut expected_parents = [0; DEGREE];
            graph
                .parents(node as usize, &mut expected_parents)
                .expect("graph parents failure");

            let parents = half_cache.read(node).expect("half cache read failure");
            assert_eq!(expected_parents, parents);

            let parents = quarter_cache
                .read(node)
                .expect("quarter cache read failure");
            assert_eq!(expected_parents, parents);

            // some internal checks to make sure the cache works as expected
            assert_eq!(
                half_cache.cache.data.len() / DEGREE / NODE_BYTES,
                nodes as usize / 2
            );
            assert_eq!(
                quarter_cache.cache.data.len() / DEGREE / NODE_BYTES,
                nodes as usize / 4
            );
        }

        half_cache.reset().expect("half cache reset failure");
        quarter_cache.reset().expect("quarter cache reset failure");

        for node in 0..nodes {
            let mut expected_parents = [0; DEGREE];
            graph
                .parents(node as usize, &mut expected_parents)
                .expect("graph parents failure");

            let parents = half_cache.read(node).expect("half cache read failure");
            assert_eq!(expected_parents, parents);

            let parents = quarter_cache
                .read(node)
                .expect("quarter cache read failure");
            assert_eq!(expected_parents, parents);
        }
    }
}
