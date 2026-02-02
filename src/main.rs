use actix_web::{web, App, HttpServer, HttpResponse, put, post};
use std::fs;
use std::sync::Mutex;
use std::collections::HashSet;
use sha2::{Sha256, Digest};
use serde::Serialize;

#[derive(Serialize)]
struct SafeResponse<'a> {
    result: &'a str,
}

#[derive(Serialize)]
struct MalwareResponseHash<'a> {
    result: &'a str,
    detection: &'a str,
    hash: String,
}

#[derive(Serialize)]
struct MalwareResponseYara<'a> {
    result: &'a str,
    detection: &'a str,
    rules: Vec<String>,
}

type RulesState = web::Data<Mutex<yara_x::Rules>>;
type HashesState = web::Data<Mutex<HashSet<String>>>;

#[derive(Debug)]
pub struct CompileStats {
    pub success: usize,
    pub failed: usize,
    pub failed_rules: Vec<String>,
}

impl CompileStats {
    pub fn new() -> Self {
        CompileStats {
            success: 0,
            failed: 0,
            failed_rules: Vec::new(),
        }
    }
}

fn load_hashes() -> HashSet<String> {
    let content = fs::read_to_string("full_sha256.txt")
        .expect("Failed to load hash database");

    content
        .lines()
        .map(|s| s.trim().to_string())
        .collect()
}

fn compile_rules() -> Result<(yara_x::Rules, CompileStats), String> {
    let mut compiler = yara_x::Compiler::new();
    let mut stats = CompileStats::new();
    
    // Add main YARA rules file
    let main_file = "./packages/full/yara-rules-full.yar";
    match fs::read_to_string(main_file) {
        Ok(source) => {
            match compiler.add_source(source.as_str()) {
                Ok(_) => {
                    println!("Loaded main YARA rules from: {}", main_file);
                    stats.success += 1;
                }
                Err(e) => {
                    eprintln!("Warning: Failed to add main rules: {}", e);
                    stats.failed += 1;
                    stats.failed_rules.push(main_file.to_string());
                }
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to read {}: {}", main_file, e);
            stats.failed += 1;
            stats.failed_rules.push(main_file.to_string());
        }
    }
    
    // Add all YARA files from ./yaraify directory
    let yaraify_dir = "./yaraify";
    if let Ok(entries) = fs::read_dir(yaraify_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                    match fs::read_to_string(&path) {
                        Ok(content) => {
                            match compiler.add_source(content.as_str()) {
                                Ok(_) => {
                                    println!("Loaded YARA rules from: {:?}", path);
                                    stats.success += 1;
                                }
                                Err(e) => {
                                    eprintln!("Warning: Failed to add rules from {:?}: {}", path, e);
                                    stats.failed += 1;
                                    stats.failed_rules.push(path.to_string_lossy().to_string());
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to read {:?}: {}", path, e);
                            stats.failed += 1;
                            stats.failed_rules.push(path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    } else {
        println!("Warning: ./yaraify directory not found, using only main rules");
    }
    
    Ok((compiler.build(), stats))
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
async fn recompile_rules(rules_state: RulesState) -> HttpResponse {
    match compile_rules() {
        Ok((new_rules, stats)) => {
            let mut rules = rules_state.lock().unwrap();
            *rules = new_rules;
            let response = format!(
                "Rules recompiled successfully!\nStats: {} loaded, {} failed\nFailed rules: {:?}",
                stats.success, stats.failed, stats.failed_rules
            );
            HttpResponse::Ok().body(response)
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Recompile failed: {}", e))
    }
}

#[post("/reload_hash")]
async fn reload_hash(hashes_state: HashesState) -> HttpResponse {
    let new_hashes = load_hashes();
    let mut hashes = hashes_state.lock().unwrap();
    *hashes = new_hashes;
    let response = format!("Hashes reloaded successfully! Loaded {} hashes.", hashes.len());
    HttpResponse::Ok().body(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Compiling YARA rules...");
    let (rules, stats) = match compile_rules() {
        Ok((r, s)) => (r, s),
        Err(e) => {
            eprintln!("Failed to compile rules: {}", e);
            std::process::exit(1);
        }
    };
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
