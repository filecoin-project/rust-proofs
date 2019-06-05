#[macro_use]
extern crate serde;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::process::Command;
use std::string::ToString;
use std::time::{Duration, SystemTime};

use clap::{App, Arg};
use failure::Error;
use glob::glob;
use human_size::{Byte, Kibibyte, SpecificSize};
use permutate::Permutator;
use prettytable::{format, Cell, Row, Table};
use regex::Regex;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};

type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, Deserialize)]
struct Case {
    challenges: Vec<usize>,
    size: Vec<Size>,
    sloth: Vec<usize>,
    m: Vec<usize>,

    command: Option<String>,
    expansion: Option<Vec<usize>>,
    hasher: Option<Vec<String>>,
    layers: Option<Vec<usize>>,
    partitions: Option<Vec<usize>>,
    taper: Option<Vec<f64>>,
    taper_layers: Option<Vec<usize>>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
struct Size(SpecificSize<Byte>);

impl Default for Size {
    fn default() -> Self {
        Size(SpecificSize::new(0, Byte).unwrap())
    }
}

impl ToString for Size {
    fn to_string(&self) -> String {
        // return as KiB as that is what the examples expect
        let kb: SpecificSize<Kibibyte> = self.0.into();
        kb.value().to_string()
    }
}

impl Serialize for Size {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Size {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SizeVisitor;

        impl<'de> Visitor<'de> for SizeVisitor {
            type Value = Size;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("user ID as a number or string")
            }

            fn visit_u64<E>(self, size: u64) -> ::std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                SpecificSize::new(size as f64, Byte)
                    .map(Size)
                    .map_err(de::Error::custom)
            }

            fn visit_str<E>(self, size: &str) -> ::std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                size.parse().map(Size).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(SizeVisitor)
    }
}

impl Case {
    pub fn params(&self) -> Vec<Vec<String>> {
        let mut res = Vec::new();

        res.push(self.challenges.iter().map(ToString::to_string).collect());
        res.push(self.size.iter().map(ToString::to_string).collect());
        res.push(self.sloth.iter().map(ToString::to_string).collect());
        res.push(self.m.iter().map(ToString::to_string).collect());

        if let Some(ref hasher) = self.hasher {
            res.push(hasher.iter().map(ToString::to_string).clone().collect());
        }

        if let Some(ref expansion) = self.expansion {
            res.push(expansion.iter().map(ToString::to_string).clone().collect());
        }

        if let Some(ref layers) = self.layers {
            res.push(layers.iter().map(ToString::to_string).clone().collect());
        }

        if let Some(ref partitions) = self.partitions {
            res.push(partitions.iter().map(ToString::to_string).clone().collect());
        }

        if let Some(ref taper) = self.taper {
            res.push(taper.iter().map(ToString::to_string).clone().collect());
        }

        if let Some(ref taper_layers) = self.taper_layers {
            res.push(
                taper_layers
                    .iter()
                    .map(ToString::to_string)
                    .clone()
                    .collect(),
            );
        }

        res
    }

    pub fn get_param_name(&self, i: usize) -> Result<String> {
        let params = self.get_param_names();
        if i > params.len() {
            return Err(format_err!("invalid param index {}", i));
        }

        Ok(params[i].to_string())
    }

    pub fn get_param_names(&self) -> Vec<String> {
        let mut res = vec![
            "challenges".to_owned(),
            "size".to_owned(),
            "sloth".to_owned(),
            "m".to_owned(),
        ];

        if self.hasher.is_some() {
            res.push("hasher".to_owned());
        }

        if self.expansion.is_some() {
            res.push("expansion".to_owned());
        }

        if self.layers.is_some() {
            res.push("layers".to_owned());
        }

        if self.partitions.is_some() {
            res.push("partitions".to_owned());
        }

        if self.taper.is_some() {
            res.push("taper".to_owned());
        }

        if self.taper_layers.is_some() {
            res.push("taper-layers".to_owned());
        }

        res
    }
}

#[cfg(not(target_os = "macos"))]
const TIME_CMD: &str = "/usr/bin/time";

#[cfg(target_os = "macos")]
const TIME_CMD: &str = "gtime";

/// The directory in which we expect the compiled binaries to be in.
const BINARY_DIR: &str = "target/release/examples";

/// The glob of which files to clear out before starting the run.
const CACHE_DIR: &str = "/tmp/filecoin-proofs-cache-*";

/// The directory in which the benchmark results will be stored.
const RESULT_DIR: &str = ".bencher";

lazy_static! {
    static ref PRELUDE: Vec<(&'static str, Vec<&'static str>)> =
        vec![("cargo", vec!["build", "--all", "--examples", "--release"]),];
    static ref MARKDOWN_TABLE_FORMAT: format::TableFormat = format::FormatBuilder::new()
        .column_separator('|')
        .borders('|')
        .separators(
            &[format::LinePosition::Title],
            format::LineSeparator::new('-', '|', '|', '|'),
        )
        .padding(1, 1)
        .build();
}

fn combine<'a, T: ?Sized>(options: &'a [&'a [&'a T]]) -> Vec<Vec<&'a T>> {
    Permutator::new(options).collect()
}

fn run(config_path: &str, print_table: bool) -> Result<()> {
    println!("reading config \"{}\"...", config_path);

    let mut f = File::open(config_path)?;
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    let config: HashMap<String, Case> = toml::from_str(&contents)?;

    println!("preparing...");

    // make sure we are cleaning up the cache
    for file in glob(CACHE_DIR)? {
        fs::remove_file(file?)?;
    }

    for (cmd, args) in &PRELUDE[..] {
        let output = Command::new(cmd).args(args).output()?;
        if !output.status.success() {
            return Err(format_err!(
                "failed to execute '{} {:?}': {} stdout: {}, stdout: {}",
                cmd,
                args,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
        }
    }

    for (name, example) in config.iter() {
        match run_benchmark(name, example) {
            Ok(results) => {
                if print_table {
                    print_result_table(name, example, &results);
                }
            }
            Err(error) => {
                eprintln!("error: {}", error);
            }
        }
    }

    Ok(())
}

fn print_result_table(name: &str, example: &Case, results: &[BenchmarkResult]) {
    let params = example.get_param_names();

    let mut table = Table::new();
    table.set_format(*MARKDOWN_TABLE_FORMAT);

    let mut titles: Vec<&str> = vec![
        "name",
        "size",
        "proving",
        "verifying",
        "params gen",
        "replication",
        "max resident set size",
    ];

    titles.extend(params.iter().map(String::as_str));

    table.set_titles(Row::new(titles.iter().map(|v| Cell::new(v)).collect()));

    for res in results {
        let timing = res.time_res.max_resident_set_size.to_string();
        let mut values: Vec<&str> = vec![
            name,
            &res.log_res
                .config
                .get("data_size")
                .map(String::as_str)
                .unwrap_or_else(|| ""),
            &res.log_res
                .stats
                .get("avg_proving_time")
                .map(String::as_str)
                .unwrap_or_else(|| ""),
            &res.log_res
                .stats
                .get("avg_verifying_time")
                .map(String::as_str)
                .unwrap_or_else(|| ""),
            res.log_res
                .stats
                .get("params_generation_time")
                .map(String::as_str)
                .unwrap_or_else(|| ""),
            res.log_res
                .stats
                .get("replication_time")
                .map(String::as_str)
                .unwrap_or_else(|| ""),
            &timing,
        ];
        values.extend(res.combination.iter().map(String::as_str));

        table.add_row(Row::new(values.into_iter().map(Cell::new).collect()));
    }

    println!("\n");
    table.printstd();
    println!("\n");
}

#[derive(Default, Debug, Serialize)]
struct TimeResult {
    // Command being timed: "/Users/dignifiedquire/work/filecoin/rust-proofs/target/release/examples/drgporep-vanilla --challenges 1 --size 1 --sloth 0 --m 6 --hasher sha256"
    command: String,
    // User time (seconds): 118.33
    user_time: f64,
    // System time (seconds): 1.07
    system_time: f64,
    // Percent of CPU this job got: 959%
    cpu: usize,
    // Elapsed (wall clock) time (h:mm:ss or m:ss): 0:12.44
    elapsed_time: Duration,
    // Average shared text size (kbytes): 0
    avg_shared_text_size: usize,
    // Average unshared data size (kbytes): 0
    avg_unshared_data_size: usize,
    // Average stack size (kbytes): 0
    avg_stack_size: usize,
    // Average total size (kbytes): 0
    avg_total_size: usize,
    // Maximum resident set size (kbytes): 117604
    max_resident_set_size: usize,
    // Average resident set size (kbytes): 0
    avg_resident_set_size: usize,
    // Major (requiring I/O) page faults: 0
    major_page_faults: usize,
    // Minor (reclaiming a frame) page faults: 69788
    minor_page_faults: usize,
    // Voluntary context switches: 7
    voluntary_context_switches: usize,
    // Involuntary context switches: 70063
    involuntary_context_switches: usize,
    // Swaps: 0
    swaps: usize,
    // File system inputs: 0
    file_system_inputs: usize,
    // File system outputs: 0
    file_system_outputs: usize,
    // Socket messages sent: 0
    socket_messages_sent: usize,
    // Socket messages received: 0
    socket_messages_received: usize,
    // Signals delivered: 0
    signals_delivered: usize,
    // Page size (bytes): 4096
    page_size: usize,
    // Exit status: 0
    exit_status: usize,
}

impl TimeResult {
    fn from_str(raw: &str) -> Result<Self> {
        let mut res = TimeResult::default();

        for line in raw.trim().split('\n') {
            let line = line.trim();
            let kv = line.split(": ").collect::<Vec<&str>>();
            let key = kv[0].trim();
            let value = kv[1].trim();

            match key {
                "Command being timed" => {
                    res.command = value.trim_matches('"').to_string();
                }
                "User time (seconds)" => {
                    res.user_time = value.parse()?;
                }
                "System time (seconds)" => {
                    res.system_time = value.parse()?;
                }
                "Percent of CPU this job got" => {
                    res.cpu = value.replace('%', "").parse()?;
                }
                "Elapsed (wall clock) time (h:mm:ss or m:ss)" => {
                    let parts = value.split(':').collect::<Vec<&str>>();
                    match parts.len() {
                        2 => {
                            let minutes = Duration::from_secs(parts[0].parse::<u64>()? * 60);
                            let seconds =
                                Duration::from_millis((parts[1].parse::<f64>()? * 1000.0) as u64);
                            res.elapsed_time = minutes + seconds;
                        }
                        3 => {
                            let hours = Duration::from_secs(parts[0].parse::<u64>()? * 60 * 60);
                            let minutes = Duration::from_secs(parts[1].parse::<u64>()? * 60);
                            let seconds =
                                Duration::from_millis((parts[2].parse::<f64>()? * 1000.0) as u64);
                            res.elapsed_time = hours + minutes + seconds;
                        }
                        _ => return Err(format_err!("invalid time format: '{}'", value)),
                    }
                }
                "Average shared text size (kbytes)" => {
                    res.avg_shared_text_size = value.parse()?;
                }
                "Average unshared data size (kbytes)" => {
                    res.avg_unshared_data_size = value.parse()?;
                }
                "Average stack size (kbytes)" => {
                    res.avg_stack_size = value.parse()?;
                }
                "Average total size (kbytes)" => {
                    res.avg_total_size = value.parse()?;
                }
                "Maximum resident set size (kbytes)" => {
                    res.max_resident_set_size = value.parse()?;
                }
                "Average resident set size (kbytes)" => {
                    res.avg_resident_set_size = value.parse()?;
                }
                "Major (requiring I/O) page faults" => {
                    res.major_page_faults = value.parse()?;
                }
                "Minor (reclaiming a frame) page faults" => {
                    res.minor_page_faults = value.parse()?;
                }
                "Voluntary context switches" => {
                    res.voluntary_context_switches = value.parse()?;
                }
                "Involuntary context switches" => {
                    res.involuntary_context_switches = value.parse()?;
                }
                "Swaps" => {
                    res.swaps = value.parse()?;
                }
                "File system inputs" => {
                    res.file_system_inputs = value.parse()?;
                }
                "File system outputs" => {
                    res.file_system_outputs = value.parse()?;
                }
                "Socket messages sent" => {
                    res.socket_messages_sent = value.parse()?;
                }
                "Socket messages received" => {
                    res.socket_messages_received = value.parse()?;
                }
                "Signals delivered" => {
                    res.signals_delivered = value.parse()?;
                }
                "Page size (bytes)" => {
                    res.page_size = value.parse()?;
                }
                "Exit status" => {
                    res.exit_status = value.parse()?;
                }
                _ => {
                    return Err(format_err!("unknown key: {}", key));
                }
            }
        }

        Ok(res)
    }
}

#[derive(Default, Debug, Serialize)]
struct BenchmarkResult {
    combination: Vec<String>,
    stdout: String,
    stderr: String,
    time_res: TimeResult,
    log_res: LogResult,
}

impl BenchmarkResult {
    pub fn new(combination: &[&str], stdout: &str, stderr: &str) -> Result<Self> {
        // removes the annoying progress bar
        let stderr = "Command being timed".to_owned()
            + stderr.split("Command being timed").collect::<Vec<&str>>()[1];

        let time_res = TimeResult::from_str(&stderr)?;
        let log_res = LogResult::from_str(&stdout)?;

        Ok(BenchmarkResult {
            combination: combination.iter().map(ToString::to_string).collect(),
            stdout: stdout.to_owned(),
            stderr,
            time_res,
            log_res,
        })
    }
}

#[derive(Default, Debug, Serialize)]
struct LogResult {
    config: HashMap<String, String>,
    stats: HashMap<String, String>,
}

impl LogResult {
    fn from_str(raw: &str) -> Result<Self> {
        let lines = raw.trim().split('\n').filter_map(|l| {
            if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(l) {
                let raw = &parsed["msg"];
                let system = parsed.get("target").cloned().unwrap_or_default();
                let kv = raw.trim().split(": ").collect::<Vec<&str>>();
                let key = kv[0].trim();
                let value = if kv.len() > 1 { kv[1].trim() } else { "" };

                Some((system, String::from(key), String::from(value)))
            } else {
                None
            }
        });

        let mut config = HashMap::new();
        let mut stats = HashMap::new();

        for (system, key, value) in lines {
            match system.as_ref() {
                "config" => {
                    config.insert(key.to_owned(), value.to_owned());
                }
                "stats" => {
                    stats.insert(key.to_owned(), value.to_owned());
                }
                // ignoring unknown subsystems for now
                _ => {}
            }
        }

        Ok(LogResult { config, stats })
    }
}

fn run_benchmark(name: &str, config: &Case) -> Result<Vec<BenchmarkResult>> {
    println!("benchmarking example: {}", name);

    // create dir to store results
    let result_dir = env::current_dir()?.join(RESULT_DIR).join(name);
    fs::create_dir_all(&result_dir)?;

    // the dance below is to avoid copies
    let params = config.params();
    let tmp_1: Vec<Vec<&str>> = params
        .iter()
        .map(|list| list.iter().map(AsRef::as_ref).collect::<Vec<&str>>())
        .collect();
    let tmp_2: Vec<&[&str]> = tmp_1.iter().map(AsRef::as_ref).collect();

    let combinations = combine(&tmp_2[..]);

    let binary_path = fs::canonicalize(BINARY_DIR)?.join(name);

    let mut results = Vec::with_capacity(combinations.len());

    for combination in &combinations {
        let mut cmd = Command::new(TIME_CMD);
        cmd.arg("-v").arg(&binary_path);

        let mut print_comb = "\t".to_owned();
        for (i, param) in combination.iter().enumerate() {
            let n = config.get_param_name(i)?;
            cmd.arg(format!("--{}", n)).arg(param);
            print_comb += &format!("{}: {}\t", n, param);
        }
        println!("{}", print_comb);

        if let Some(ref command) = config.command {
            cmd.arg(command);
        }

        let output = cmd.output()?;
        let res = BenchmarkResult::new(
            combination,
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        )?;

        match output.status.code() {
            Some(code) => {
                if code != 0 {
                    eprintln!("{}", &String::from_utf8_lossy(&output.stderr));
                    return Err(format_err!("benchmark exited with non-zero status"));
                }
            }
            None => {
                return Err(format_err!("benchmark terminated by signal"));
            }
        }

        let mut data = serde_json::to_string(&res)?;
        data.push('\n');
        results.push(res);

        // store result on disk
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let filename = result_dir.join(format!(
            "{}-{}.json",
            combination.join("-"),
            timestamp.as_secs(),
        ));

        fs::write(filename, data)?;
    }

    Ok(results)
}

fn main() {
    // the bencher output-parsing code requires JSON, and an environment
    // variable is the mechanism for enabling JSON-log support
    std::env::set_var("FIL_PROOFS_LOG_JSON", "true");

    let matches = App::new("Rust Proofs Bencher")
        .version("1.0")
        .about("Benchmark all the things")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .default_value("bench.config.toml")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("table")
                .long("table")
                .takes_value(false)
                .help("Print a summary as markdown table"),
        )
        .get_matches();

    let config = matches.value_of("config").unwrap();
    let print_table = matches.is_present("table");

    std::process::exit(match run(config, print_table) {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("error: {:?}", err);
            1
        }
    });
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Interval {
    start: f64,
    end: f64,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct CriterionResult {
    name: String,
    samples: u32,
    time_med_us: f64,
    time_us: Interval,
    slope_us: Interval,
    mean_us: Interval,
    median_us: Interval,
    r_2: Interval,
    std_dev_us: Interval,
    med_abs_dev: Interval,
}

fn make_detail_re(name: &str) -> Regex {
    Regex::new(&format!(r"{}\s+\[(\d+\.\d+ \w+) (\d+\.\d+ \w+)\]", name)).expect("invalid regex")
}

/// Parses the output of `cargo bench -p storage-proofs --bench <benchmark> -- --verbose --colors never`.
fn parse_criterion_out(s: impl AsRef<str>) -> Result<Vec<CriterionResult>> {
    let mut res = Vec::new();

    let start_re = Regex::new(r"^Benchmarking ([^:]+)$").expect("invalid regex");
    let sample_re = Regex::new(r"Collecting (\d+) samples").expect("invalid regex");
    let time_re = Regex::new(r"time:\s+\[(\d+\.\d+ \w+) (\d+\.\d+ \w+) (\d+\.\d+ \w+)\]")
        .expect("invalid regex");

    let slope_re = make_detail_re("slope");
    let r_2_re = Regex::new(r"R\^2\s+\[(\d+\.\d+) (\d+\.\d+)\]").expect("invalid regex");
    let mean_re = make_detail_re("mean");
    let std_dev_re = make_detail_re(r"std\. dev\.");
    let median_re = make_detail_re("median");
    let med_abs_dev_re = make_detail_re(r"med\. abs\. dev\.");

    let mut current: Option<(
        String,
        Option<u32>,
        Option<f64>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
        Option<Interval>,
    )> = None;

    for line in s.as_ref().lines() {
        if let Some(caps) = start_re.captures(line) {
            if current.is_some() {
                let r = current.take().unwrap();
                res.push(CriterionResult {
                    name: r.0,
                    samples: r.1.unwrap_or_default(),
                    time_med_us: r.2.unwrap_or_default(),
                    time_us: r.3.unwrap_or_default(),
                    slope_us: r.4.unwrap_or_default(),
                    mean_us: r.5.unwrap_or_default(),
                    median_us: r.6.unwrap_or_default(),
                    r_2: r.7.unwrap_or_default(),
                    std_dev_us: r.8.unwrap_or_default(),
                    med_abs_dev: r.9.unwrap_or_default(),
                });
            }
            current = Some((
                caps[1].to_string(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ));
            println!("got start: {:?}", caps);
        }

        if let Some(ref mut current) = current {
            // Samples
            if let Some(caps) = sample_re.captures(line) {
                current.1 = Some(caps[1].parse().unwrap_or_default());
            }

            // Time
            if let Some(caps) = time_re.captures(line) {
                current.2 = Some(time_to_us(&caps[2]));
                current.3 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[3]),
                });
            }

            // Slope
            if let Some(caps) = slope_re.captures(line) {
                current.4 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }
            // R^2
            if let Some(caps) = r_2_re.captures(line) {
                current.7 = Some(Interval {
                    start: caps[1].parse().unwrap(),
                    end: caps[2].parse().unwrap(),
                });
            }

            // Mean
            if let Some(caps) = mean_re.captures(line) {
                current.5 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }

            // std.dev
            if let Some(caps) = std_dev_re.captures(line) {
                current.8 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }

            // median
            if let Some(caps) = median_re.captures(line) {
                current.6 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }

            // med.abs.dev
            if let Some(caps) = med_abs_dev_re.captures(line) {
                current.9 = Some(Interval {
                    start: time_to_us(&caps[1]),
                    end: time_to_us(&caps[2]),
                });
            }
        }
    }

    if current.is_some() {
        let r = current.take().unwrap();
        res.push(CriterionResult {
            name: r.0,
            samples: r.1.unwrap_or_default(),
            time_med_us: r.2.unwrap_or_default(),
            time_us: r.3.unwrap_or_default(),
            slope_us: r.4.unwrap_or_default(),
            mean_us: r.5.unwrap_or_default(),
            median_us: r.6.unwrap_or_default(),
            r_2: r.7.unwrap_or_default(),
            std_dev_us: r.8.unwrap_or_default(),
            med_abs_dev: r.9.unwrap_or_default(),
        });
    }
    Ok(res)
}

/// parses a string of the form "123.12 us".
fn time_to_us(s: &str) -> f64 {
    let parts = s.trim().split_whitespace().collect::<Vec<_>>();
    assert_eq!(parts.len(), 2, "invalid val: {:?}", parts);
    let ts: f64 = parts[0].parse().expect("invalid number");
    match parts[1] {
        "ns" => ts / 1000.,
        "us" => ts,
        "ms" => ts * 1000.,
        "s" => ts * 1000. * 1000.,
        _ => panic!("unknown unit: {}", parts[1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine() {
        let input = vec![vec!["1", "2", "3"], vec!["4", "5"]];
        let refs: Vec<&[&str]> = input.iter().map(AsRef::as_ref).collect();
        assert_eq!(
            combine(&refs[..]),
            vec![
                vec!["1", "4"],
                vec!["1", "5"],
                vec!["2", "4"],
                vec!["2", "5"],
                vec!["3", "4"],
                vec!["3", "5"]
            ],
        );
    }

    #[test]
    fn test_time_result_from_str() {
        let res = TimeResult::from_str("
	Command being timed: \"/Users/dignifiedquire/work/filecoin/rust-proofs/target/release/examples/drgporep-vanilla --challenges 1 --size 1 --sloth 0 --m 6 --hasher sha256\"
	User time (seconds): 0.01
	System time (seconds): 0.01
	Percent of CPU this job got: 184%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.01
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
	Maximum resident set size (kbytes): 6932
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 1932
	Voluntary context switches: 0
	Involuntary context switches: 889
	Swaps: 0
	File system inputs: 0
	File system outputs: 0
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 0
").unwrap();

        assert_eq!(res.command, "/Users/dignifiedquire/work/filecoin/rust-proofs/target/release/examples/drgporep-vanilla --challenges 1 --size 1 --sloth 0 --m 6 --hasher sha256");
        assert_eq!(res.user_time, 0.01);
        assert_eq!(res.swaps, 0);
        assert_eq!(res.involuntary_context_switches, 889);
        assert_eq!(res.cpu, 184);
        assert_eq!(res.elapsed_time, Duration::from_millis(10));
    }

    #[test]
    fn test_log_results_str_json() {
        let res = LogResult::from_str("
{\"msg\":\"constraint system: Groth\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.315918-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:86 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"data_size:  1 kB\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.316948-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:87 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"challenge_count: 1\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.316961-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:88 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"m: 6\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.316970-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:89 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"sloth: 0\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.316978-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:90 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"tree_depth: 5\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.317011-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:91 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"reading groth params from cache: \\\"/tmp/filecoin-proofs-cache-multi-challenge merklepor-1024-1-6-0\\\"\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.317046-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:102 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"params\"}
{\"msg\":\"generating verification key\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.388725-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:123 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"params\"}
{\"msg\":\"avg_proving_time: 0.213533235 seconds\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:20.480250-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:180 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"stats\"}
{\"msg\":\"avg_verifying_time: 0.003935171 seconds\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:20.480273-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:181 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"stats\"}
{\"msg\":\"params_generation_time: 76.536768ms\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:20.480283-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:182 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"stats\"}

").unwrap();

        assert_eq!(res.config.get("constraint system").unwrap(), "Groth");
        assert_eq!(res.config.get("data_size").unwrap(), "1 kB",);
        assert_eq!(
            res.stats.get("avg_proving_time").unwrap(),
            "0.213533235 seconds"
        );
    }

    #[test]
    fn test_time_to_us() {
        assert_eq!(time_to_us("123.12 us"), 123.12);
        assert_eq!(time_to_us("1.0 s"), 1_000_000.);
    }

    #[test]
    fn test_parse_criterion() {
        let stdout = "Benchmarking merkletree/blake2s/128
Benchmarking merkletree/blake2s/128: Warming up for 3.0000 s
Benchmarking merkletree/blake2s/128: Collecting 20 samples in estimated 5.0192 s (39060 iterations)
Benchmarking merkletree/blake2s/128: Analyzing
merkletree/blake2s/128  time:   [141.11 us 151.42 us 159.66 us]
                        change: [-25.163% -21.490% -17.475%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 20 measurements (20.00%)
  1 (5.00%) high mild
  3 (15.00%) high severe
slope  [141.11 us 159.66 us] R^2            [0.8124914 0.8320154]
mean   [140.55 us 150.62 us] std. dev.      [5.6028 us 15.213 us]
median [138.33 us 143.23 us] med. abs. dev. [1.7507 us 8.4109 us]";

        let parsed = parse_criterion_out(stdout).unwrap();
        assert_eq!(
            parsed,
            vec![CriterionResult {
                name: "merkletree/blake2s/128".into(),
                samples: 20,
                time_med_us: 151.42,
                time_us: Interval {
                    start: 141.11,
                    end: 159.66
                },
                slope_us: Interval {
                    start: 141.11,
                    end: 159.66
                },
                mean_us: Interval {
                    start: 140.55,
                    end: 150.62
                },
                median_us: Interval {
                    start: 138.33,
                    end: 143.23
                },
                r_2: Interval {
                    start: 0.8124914,
                    end: 0.8320154
                },
                std_dev_us: Interval {
                    start: 5.6028,
                    end: 15.213
                },
                med_abs_dev: Interval {
                    start: 1.7507,
                    end: 8.4109
                },
            }]
        );
    }
}
