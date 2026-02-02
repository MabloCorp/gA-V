use actix_web::{web, App, HttpServer, HttpResponse, put, post};
use std::fs;
use std::sync::Mutex;
use std::collections::HashSet;
use std::path::PathBuf;
use sha2::{Sha256, Digest};
use serde::Serialize;

#[derive(Serialize)]
#[serde(untagged)]
enum ScanResponse {
    Safe { result: String },
    MalwareHash { result: String, detection: String, hash: String },
    MalwareYara { result: String, detection: String, rules: Vec<String> },
}

type RulesState = web::Data<Mutex<yara_x::Rules>>;
type HashesState = web::Data<Mutex<HashSet<String>>>;

#[derive(Debug, Default, Serialize)]
pub struct CompileStats {
    pub success: usize,
    pub failed: usize,
    pub failed_rules: Vec<String>,
}

fn load_hashes() -> HashSet<String> {
    let content = fs::read_to_string("full_sha256.txt")
        .expect("Failed to load hash database");

    content
        .lines()
        .map(|s| s.trim().to_string())
        .collect()
}

fn compile_rules() -> (yara_x::Rules, CompileStats) {
    let mut compiler = yara_x::Compiler::new();
    let mut stats = CompileStats::default();

    // Collect all paths
    let mut paths: Vec<PathBuf> = vec![PathBuf::from("./packages/full/yara-rules-full.yar")];
    
    if let Ok(entries) = fs::read_dir("./yaraify") {
        paths.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "yar")));
    }

    // Process each path
    for path in paths {
        let result = fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|src| compiler.add_source(src.as_str()).map_err(|e| e.to_string()));

        match result {
            Ok(_) => {
                stats.success += 1;
            }
            Err(e) => {
                eprintln!("Warning: Failed to load {:?}: {}", path, e);
                stats.failed += 1;
                stats.failed_rules.push(path.to_string_lossy().to_string());
            }
        }
    }

    (compiler.build(), stats)
}

#[put("/send")]
async fn scan_file(rules_state: RulesState, hashes_state: HashesState, payload: web::Bytes) -> HttpResponse {
    // Calculate SHA256 of the payload
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let hash_result = hasher.finalize();
    let hash_hex = hex::encode(hash_result);

    // Check if the hash is in the malware list
    let hashes = hashes_state.lock().unwrap();
    if hashes.contains(&hash_hex) {
        let response = MalwareResponseHash {
            result: "malware",
            detection: "hash",
            hash: hash_hex,
        };
        return HttpResponse::Ok().json(response);
    }

    // Get the rules and scan
    let rules = rules_state.lock().unwrap();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = match scanner.scan(&payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Scan failed: {}", e);
            return HttpResponse::InternalServerError().body("Scan failed");
        }
    };

    // Debug: print summary of scan results
    let matching_rules = results.matching_rules();
    let rules_count = matching_rules.len();

    println!("Scan completed. matching_rules_count={}", rules_count);
    if rules_count > 0 {
        println!("Matched rules present (count={})", rules_count);
    }
    
    if rules_count > 0 {
        let response = MalwareResponseYara {
            result: "malware",
            detection: "YARA",
            rules: matching_rules.map(|r| r.identifier().to_string()).collect(),
        };
        HttpResponse::Ok().json(response)
    } else {
        let response = SafeResponse {
            result: "safe",
        };
        HttpResponse::Ok().json(response)
    }
}

#[post("/recompile")]
async fn recompile_rules(state: RulesState) -> HttpResponse {
    let (new_rules, stats) = compile_rules();

    // Lock, swap the data, and drop the lock immediately
    *state.lock().unwrap() = new_rules;

    HttpResponse::Ok().json(stats)
}

#[post("/reload_hash")]
async fn reload_hash(state: HashesState) -> HttpResponse {
    let new_hashes = load_hashes();
    let count = new_hashes.len();

    // Lock, swap the data, and drop the lock immediately
    *state.lock().unwrap() = new_hashes;

    HttpResponse::Ok().body(format!("Hashes reloaded successfully! {count} signatures active."))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Compiling YARA rules...");
    let (rules, stats) = compile_rules();
    println!("Rules compiled successfully!");
    println!("Stats: {} loaded, {} failed", stats.success, stats.failed);
    if !stats.failed_rules.is_empty() {
        println!("Failed rules: {:?}", stats.failed_rules);
    }

    println!("Loading SHA256 hashes...");
    let hashes = load_hashes();
    println!("Loaded {} hashes.", hashes.len());

    let rules_state = web::Data::new(Mutex::new(rules));
    let hashes_state = web::Data::new(Mutex::new(hashes));

    println!("Starting server on http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(rules_state.clone())
            .app_data(hashes_state.clone())
            .service(scan_file)
            .service(recompile_rules)
            .service(reload_hash)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
