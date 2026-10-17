use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use std::{
    env, fs,
    hint::black_box,
    io::Read,
    sync::{Arc, Barrier},
    thread,
    time::Instant,
};

type Failure = Box<dyn std::error::Error + Send + Sync>;

fn operation(
    hasher: &Argon2<'_>,
    password: &[u8],
    encoded: &str,
    mode: &str,
) -> Result<(), Failure> {
    match mode {
        "hash" | "change" => {
            if mode == "change" {
                hasher
                    .verify_password(password, encoded)
                    .map_err(|e| e.to_string())?;
            }
            let mut salt = [0_u8; 16];
            fs::File::open("/dev/urandom")?.read_exact(&mut salt)?;
            black_box(
                hasher
                    .hash_password_with_salt(password, &salt)
                    .map_err(|e| e.to_string())?,
            );
        }
        "verify" => hasher
            .verify_password(password, encoded)
            .map_err(|e| e.to_string())?,
        "unknown" => {
            if hasher.verify_password(password, encoded).is_ok() {
                return Err("dummy verification unexpectedly succeeded".into());
            }
        }
        _ => return Err("mode must be hash, verify, unknown, or change".into()),
    }
    Ok(())
}

fn main() -> Result<(), Failure> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 {
        return Err("usage: bloc-administrator-spike MEMORY_KIB ITERATIONS CONCURRENCY SAMPLES MODE ascii|unicode".into());
    }
    let memory: u32 = args[1].parse()?;
    let iterations: u32 = args[2].parse()?;
    let concurrency: usize = args[3].parse()?;
    let samples: usize = args[4].parse()?;
    let mode = &args[5];
    if !(1..=2).contains(&concurrency) || samples < 20 || !samples.is_multiple_of(concurrency) {
        return Err(
            "concurrency must be 1 or 2; samples must be >=20 and divisible by concurrency".into(),
        );
    }
    let password = match args[6].as_str() {
        "ascii" => "synthetic benchmark password only".to_owned(),
        "unicode" => "🦀".repeat(128),
        _ => return Err("input must be ascii or unicode".into()),
    };
    let params = Params::new(memory, iterations, 1, Some(32)).map_err(|e| e.to_string())?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // Fixed salt is confined to this synthetic verification fixture; measured new hashes use OS randomness.
    let fixture_password = if mode == "unknown" {
        b"synthetic dummy verification fixture".as_slice()
    } else {
        password.as_bytes()
    };
    let encoded = hasher
        .hash_password_with_salt(fixture_password, &[42; 16])
        .map_err(|e| e.to_string())?
        .to_string();
    eprintln!(
        "architecture={} os={} memory_kib={memory} iterations={iterations} concurrency={concurrency} samples={samples} mode={mode} input={} warmups=20",
        env::consts::ARCH,
        env::consts::OS,
        args[6]
    );
    for path in [
        "/proc/version",
        "/proc/cpuinfo",
        "/sys/fs/cgroup/cpu.max",
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory.swap.max",
    ] {
        eprintln!(
            "{path}: {}",
            fs::read_to_string(path).unwrap_or_else(|_| "unavailable".into())
        );
    }
    for _ in 0..20 {
        operation(&hasher, password.as_bytes(), &encoded, mode)?;
    }
    let barrier = Arc::new(Barrier::new(concurrency));
    let mut rows = Vec::with_capacity(samples);
    thread::scope(|scope| -> Result<(), Failure> {
        let mut handles = Vec::new();
        for worker in 0..concurrency {
            let barrier = Arc::clone(&barrier);
            let hasher = &hasher;
            let password = &password;
            let encoded = &encoded;
            handles.push(
                scope.spawn(move || -> Result<Vec<(usize, usize, u128)>, Failure> {
                    let mut result = Vec::new();
                    barrier.wait();
                    for sample in 0..samples / concurrency {
                        let start = Instant::now();
                        operation(hasher, password.as_bytes(), encoded, mode)?;
                        result.push((worker, sample, start.elapsed().as_micros()));
                    }
                    Ok(result)
                }),
            );
        }
        for handle in handles {
            rows.extend(handle.join().map_err(|_| "benchmark worker panicked")??);
        }
        Ok(())
    })?;
    println!("worker,sample,duration_us");
    for (worker, sample, duration) in rows {
        println!("{worker},{sample},{duration}");
    }
    for path in [
        "/sys/fs/cgroup/memory.peak",
        "/sys/fs/cgroup/memory.events",
        "/sys/fs/cgroup/cpu.stat",
    ] {
        eprintln!(
            "{path}: {}",
            fs::read_to_string(path).unwrap_or_else(|_| "unavailable".into())
        );
    }
    Ok(())
}
