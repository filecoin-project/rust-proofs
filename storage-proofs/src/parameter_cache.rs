use crate::error::*;
use bellperson::groth16::Parameters;
use bellperson::{groth16, Circuit};
use fil_sapling_crypto::jubjub::JubjubEngine;
use fs2::FileExt;
use itertools::Itertools;
use rand::{SeedableRng, XorShiftRng};
use sha2::{Digest, Sha256};

use std::env;
use std::fs::{self, create_dir_all, File};
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::SP_LOG;

/// Bump this when circuits change to invalidate the cache.
pub const VERSION: usize = 10;

pub const PARAMETER_CACHE_DIR: &str = "/tmp/filecoin-proof-parameters/";

/// If this changes, parameters generated under different conditions may vary. Don't change it.
pub const PARAMETER_RNG_SEED: [u32; 4] = [0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654];

#[derive(Debug)]
struct LockedFile(File);

// TODO: use in memory lock as well, as file locks do not guarantee exclusive access acros OSes.

impl LockedFile {
    pub fn open_exclusive_read<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        let f = fs::OpenOptions::new().read(true).open(p)?;
        f.lock_exclusive()?;

        Ok(LockedFile(f))
    }

    pub fn open_exclusive<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(p)?;
        f.lock_exclusive()?;

        Ok(LockedFile(f))
    }
}

impl io::Write for LockedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl io::Read for LockedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl io::Seek for LockedFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl Drop for LockedFile {
    fn drop(&mut self) {
        self.0
            .unlock()
            .unwrap_or_else(|e| panic!("{}: failed to {:?} unlock file safely", e, &self.0));
    }
}

fn parameter_cache_dir_name() -> String {
    match env::var("FILECOIN_PARAMETER_CACHE") {
        Ok(dir) => dir,
        Err(_) => String::from(PARAMETER_CACHE_DIR),
    }
}

pub fn parameter_cache_dir() -> PathBuf {
    Path::new(&parameter_cache_dir_name()).to_path_buf()
}

fn parameter_cache_params_path(parameter_set_identifier: &str) -> PathBuf {
    let dir = Path::new(&parameter_cache_dir_name()).to_path_buf();
    dir.join(format!("v{}-{}.params", VERSION, parameter_set_identifier))
}

fn parameter_cache_metadata_path(parameter_set_identifier: &str) -> PathBuf {
    let dir = Path::new(&parameter_cache_dir_name()).to_path_buf();
    dir.join(format!("v{}-{}.meta", VERSION, parameter_set_identifier))
}

fn parameter_cache_verifying_key_path(parameter_set_identifier: &str) -> PathBuf {
    let dir = Path::new(&parameter_cache_dir_name()).to_path_buf();
    dir.join(format!("v{}-{}.vk", VERSION, parameter_set_identifier))
}

fn ensure_cache_path(cache_entry_path: PathBuf) -> Result<PathBuf> {
    info!(SP_LOG, "ensuring that all parent directories for: {:?} exist", cache_entry_path; "target" => "cache");

    if let Err(err) = create_dir_all(&cache_entry_path) {
        match err.kind() {
            io::ErrorKind::AlreadyExists => {}
            _ => return Err(From::from(err)),
        }
    }

    Ok(cache_entry_path)
}

pub trait ParameterSetMetadata: Clone {
    fn identifier(&self) -> String;
    fn sector_size(&self) -> Option<u64>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntryMetadata {
    pub sector_size: Option<u64>,
}

pub trait CacheableParameters<E, C, P>
where
    C: Circuit<E>,
    E: JubjubEngine,
    P: ParameterSetMetadata,
{
    fn cache_prefix() -> String;

    fn cache_meta(pub_params: &P) -> CacheEntryMetadata {
        CacheEntryMetadata {
            sector_size: pub_params.sector_size(),
        }
    }

    fn cache_identifier(pub_params: &P) -> String {
        let param_identifier = pub_params.identifier();
        info!(SP_LOG, "parameter set identifier for cache: {}", param_identifier; "target" => "params");
        let mut hasher = Sha256::default();
        hasher.input(&param_identifier.into_bytes());
        let circuit_hash = hasher.result();
        format!(
            "{}-{:02x}",
            Self::cache_prefix(),
            circuit_hash.iter().format("")
        )
    }

    fn get_param_metadata(_circuit: C, pub_params: &P) -> Result<CacheEntryMetadata> {
        let id = Self::cache_identifier(pub_params);

        // generate (or load) metadata
        let meta_path = ensure_cache_path(parameter_cache_metadata_path(&id))?;
        read_cached_metadata(&meta_path)
            .or_else(|_| write_cached_metadata(&meta_path, Self::cache_meta(pub_params)))
    }

    fn get_groth_params(circuit: C, pub_params: &P) -> Result<groth16::Parameters<E>> {
        // Always seed the rng identically so parameter generation will be deterministic.
        let id = Self::cache_identifier(pub_params);

        let generate = || {
            let rng = &mut XorShiftRng::from_seed(PARAMETER_RNG_SEED);
            info!(SP_LOG, "Actually generating groth params."; "target" => "params", "id" => &id);
            let start = Instant::now();
            let parameters = groth16::generate_random_parameters::<E, _, _>(circuit, rng);
            let generation_time = start.elapsed();
            info!(SP_LOG, "groth_parameter_generation_time: {:?}", generation_time; "target" => "stats", "id" => &id);
            parameters
        };

        // generate (or load) Groth parameters
        let cache_path = ensure_cache_path(parameter_cache_params_path(&id))?;
        read_cached_params(&cache_path).or_else(|_| write_cached_params(&cache_path, generate()?))
    }

    fn get_verifying_key(circuit: C, pub_params: &P) -> Result<groth16::VerifyingKey<E>> {
        let id = Self::cache_identifier(pub_params);

        let generate = || -> Result<groth16::VerifyingKey<E>> {
            let groth_params = Self::get_groth_params(circuit, pub_params)?;
            info!(SP_LOG, "Getting verifying key."; "target" => "verifying_key", "id" => &id);
            Ok(groth_params.vk)
        };

        // generate (or load) verifying key
        let cache_path = ensure_cache_path(parameter_cache_verifying_key_path(&id))?;
        read_cached_verifying_key(&cache_path)
            .or_else(|_| write_cached_verifying_key(&cache_path, generate()?))
    }
}

fn ensure_parent(path: &PathBuf) -> Result<()> {
    match path.parent() {
        Some(dir) => {
            create_dir_all(dir)?;
            Ok(())
        }
        None => Ok(()),
    }
}

fn read_cached_params<E: JubjubEngine>(
    cache_entry_path: &PathBuf,
) -> Result<groth16::Parameters<E>> {
    info!(SP_LOG, "checking cache_path: {:?} for parameters", cache_entry_path; "target" => "params");
    with_exclusive_read_lock(cache_entry_path, |mut f| {
        Parameters::read(&mut f, false).map_err(Error::from).map(|value| {
            info!(SP_LOG, "read parameters from cache {:?} ", cache_entry_path; "target" => "params");
            value
        })
    })
}

fn read_cached_verifying_key<E: JubjubEngine>(
    cache_entry_path: &PathBuf,
) -> Result<groth16::VerifyingKey<E>> {
    info!(SP_LOG, "checking cache_path: {:?} for verifying key", cache_entry_path; "target" => "verifying_key");
    with_exclusive_read_lock(cache_entry_path, |mut file| {
        groth16::VerifyingKey::read(&mut file).map_err(Error::from).map(|value| {
            info!(SP_LOG, "read verifying key from cache {:?} ", cache_entry_path; "target" => "verifying_key");
            value
        })
    })
}

fn read_cached_metadata(cache_entry_path: &PathBuf) -> Result<CacheEntryMetadata> {
    info!(SP_LOG, "checking cache_path: {:?} for metadata", cache_entry_path; "target" => "metadata");
    with_exclusive_read_lock(cache_entry_path, |file| {
        serde_json::from_reader(file).map_err(Error::from).map(|value| {
            info!(SP_LOG, "read metadata from cache {:?} ", cache_entry_path; "target" => "metadata");
            value
        })
    })
}

fn write_cached_metadata(
    cache_entry_path: &PathBuf,
    value: CacheEntryMetadata,
) -> Result<CacheEntryMetadata> {
    with_exclusive_lock(cache_entry_path, |file| {
        serde_json::to_writer(file, &value)
            .map_err(Error::from)
            .map(|_| {
                info!(SP_LOG, "wrote metadata to cache {:?} ", cache_entry_path; "target" => "metadata");
                value
            })
    })
}

fn write_cached_verifying_key<E: JubjubEngine>(
    cache_entry_path: &PathBuf,
    value: groth16::VerifyingKey<E>,
) -> Result<groth16::VerifyingKey<E>> {
    with_exclusive_lock(cache_entry_path, |file| {
        value.write(file).map_err(Error::from).map(|_| {
            info!(SP_LOG, "wrote verifying key to cache {:?} ", cache_entry_path; "target" => "verifying_key");
            value
        })
    })
}

fn write_cached_params<E: JubjubEngine>(
    cache_entry_path: &PathBuf,
    value: groth16::Parameters<E>,
) -> Result<groth16::Parameters<E>> {
    with_exclusive_lock(cache_entry_path, |file| {
        value.write(file).map_err(Error::from).map(|_| {
            info!(SP_LOG, "wrote groth parameters to cache {:?} ", cache_entry_path; "target" => "params");
            value
        })
    })
}

fn with_exclusive_lock<T>(
    file_path: &PathBuf,
    f: impl FnOnce(&mut LockedFile) -> Result<T>,
) -> Result<T> {
    with_open_file(file_path, LockedFile::open_exclusive, f)
}

fn with_exclusive_read_lock<T>(
    file_path: &PathBuf,
    f: impl FnOnce(&mut LockedFile) -> Result<T>,
) -> Result<T> {
    with_open_file(file_path, LockedFile::open_exclusive_read, f)
}

fn with_open_file<'a, T>(
    file_path: &'a PathBuf,
    open_file: impl FnOnce(&'a PathBuf) -> io::Result<LockedFile>,
    f: impl FnOnce(&mut LockedFile) -> Result<T>,
) -> Result<T> {
    ensure_parent(&file_path)?;
    f(&mut open_file(&file_path)?)
}
