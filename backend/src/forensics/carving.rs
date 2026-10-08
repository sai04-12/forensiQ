use crate::models::FileArtifact;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// File Signature Definition in Registry
pub struct FileSignature {
    pub name: &'static str,
    pub extension: &'static str,
    pub mime_type: &'static str,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub max_size_bytes: u64,
}

pub fn get_signature_registry() -> Vec<FileSignature> {
    vec![
        FileSignature {
            name: "PDF",
            extension: "pdf",
            mime_type: "application/pdf",
            header: b"%PDF-",
            footer: Some(b"%%EOF"),
            max_size_bytes: 25 * 1024 * 1024, // 25 MB max PDF
        },
        FileSignature {
            name: "PNG",
            extension: "png",
            mime_type: "image/png",
            header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            footer: Some(b"IEND"),
            max_size_bytes: 15 * 1024 * 1024, // 15 MB max PNG
        },
        FileSignature {
            name: "JPEG",
            extension: "jpg",
            mime_type: "image/jpeg",
            header: &[0xFF, 0xD8, 0xFF],
            footer: Some(&[0xFF, 0xD9]),
            max_size_bytes: 15 * 1024 * 1024, // 15 MB max JPEG
        },
    ]
}

pub struct CarveResult {
    pub candidates_found: usize,
    pub files_recovered: usize,
    pub files_invalid: usize,
    pub duplicates_skipped: usize,
    pub carved_artifacts: Vec<FileArtifact>,
    pub source_sha256_before: String,
    pub source_sha256_after: String,
}

/// Compute SHA-256 and SHA-1 for a file path
pub fn compute_file_hashes(file_path: &str) -> Result<(String, u64), String> {
    let file =
        File::open(file_path).map_err(|e| format!("Failed to open file for hashing: {}", e))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total_bytes = 0u64;

    loop {
        let count = reader.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total_bytes += count as u64;
    }

    Ok((hex::encode(hasher.finalize()), total_bytes))
}

/// Compute SHA-256 and SHA-1 for a byte slice
pub fn compute_bytes_hashes(data: &[u8]) -> (String, String) {
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(data);
    let sha256_str = hex::encode(sha256_hasher.finalize());

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(data);
    let sha1_str = hex::encode(sha1_hasher.finalize());

    (sha256_str, sha1_str)
}

/// Real Binary File Carving Engine
pub async fn carve_evidence_file(
    evidence_path: &str,
    case_id: &str,
    evidence_id: &str,
    target_types: Option<Vec<String>>,
    carved_root_dir: &str,
) -> Result<CarveResult, String> {
    let path_obj = Path::new(evidence_path);
    if !path_obj.exists() {
        return Err(format!("Source evidence file not found: {}", evidence_path));
    }

    // 1. CRITICAL INTEGRITY CONTROL: Calculate source evidence SHA-256 BEFORE carving
    let (source_sha256_before, _evidence_file_size) = compute_file_hashes(evidence_path)?;

    // 2. Prepare Isolated Carving Output Directory: carved_output/<case_id>/<evidence_id>/
    let output_dir = PathBuf::from(carved_root_dir)
        .join(case_id)
        .join(evidence_id);

    fs::create_dir_all(&output_dir).map_err(|e| {
        format!(
            "Failed to create isolated carving workspace directory: {}",
            e
        )
    })?;

    // 3. Read Source Evidence in Read-Only Mode into Memory / Chunked Buffer
    let mut file = File::open(evidence_path)
        .map_err(|e| format!("Failed to open evidence file read-only: {}", e))?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read evidence content: {}", e))?;

    let registry = get_signature_registry();
    let requested_types: HashSet<String> = match target_types {
        Some(list) => list.into_iter().map(|s| s.to_uppercase()).collect(),
        None => vec![
            "PDF".to_string(),
            "PNG".to_string(),
            "JPEG".to_string(),
            "JPG".to_string(),
        ]
        .into_iter()
        .collect(),
    };

    let mut candidates_found = 0;
    let mut files_recovered = 0;
    let mut files_invalid = 0;
    let mut duplicates_skipped = 0;
    let mut carved_artifacts = Vec::new();
    let mut seen_hashes = HashSet::new();

    let created_at = chrono::Utc::now().format("%d-%m-%Y %H:%M:%S").to_string();

    for sig in &registry {
        let is_requested = requested_types.contains(sig.name)
            || (sig.name == "JPEG"
                && (requested_types.contains("JPG") || requested_types.contains("JPEG")));

        if !is_requested {
            continue;
        }

        let header_len = sig.header.len();
        if buffer.len() < header_len {
            continue;
        }

        let mut offset = 0;
        while offset <= buffer.len().saturating_sub(header_len) {
            if &buffer[offset..offset + header_len] == sig.header {
                candidates_found += 1;
                let start_offset = offset;

                // Determine file boundary based on file format
                let mut end_offset = None;

                match sig.name {
                    "PDF" => {
                        // Scan forward for %%EOF marker
                        let search_end =
                            (start_offset + sig.max_size_bytes as usize).min(buffer.len());
                        if let Some(footer) = sig.footer {
                            let window = &buffer[start_offset..search_end];
                            // Find all %%EOF occurrences and pick the last plausible one
                            let footer_len = footer.len();
                            let mut last_eof = None;
                            let mut pos = 0;
                            while pos <= window.len().saturating_sub(footer_len) {
                                if &window[pos..pos + footer_len] == footer {
                                    last_eof = Some(pos + footer_len);
                                }
                                pos += 1;
                            }
                            if let Some(relative_end) = last_eof {
                                // Include trailing CR/LF if present
                                let mut final_rel = relative_end;
                                while start_offset + final_rel < buffer.len()
                                    && (buffer[start_offset + final_rel] == b'\r'
                                        || buffer[start_offset + final_rel] == b'\n')
                                {
                                    final_rel += 1;
                                }
                                end_offset = Some(start_offset + final_rel);
                            }
                        }
                    }
                    "PNG" => {
                        // PNG structure check: Must have IHDR at offset + 12
                        if start_offset + 16 <= buffer.len()
                            && &buffer[start_offset + 12..start_offset + 16] == b"IHDR"
                        {
                            let search_end =
                                (start_offset + sig.max_size_bytes as usize).min(buffer.len());
                            let window = &buffer[start_offset..search_end];
                            if let Some(footer) = sig.footer {
                                let footer_len = footer.len(); // "IEND" = 4 bytes
                                let mut pos = 0;
                                while pos <= window.len().saturating_sub(footer_len + 4) {
                                    if &window[pos..pos + footer_len] == footer {
                                        // IEND chunk has 4 bytes CRC after it
                                        end_offset = Some(start_offset + pos + footer_len + 4);
                                        break;
                                    }
                                    pos += 1;
                                }
                            }
                        }
                    }
                    "JPEG" => {
                        // Scan forward for FF D9 EOI marker
                        let search_end =
                            (start_offset + sig.max_size_bytes as usize).min(buffer.len());
                        let window = &buffer[start_offset..search_end];
                        if let Some(footer) = sig.footer {
                            let footer_len = footer.len();
                            let mut pos = 2; // Skip SOI FF D8
                            while pos <= window.len().saturating_sub(footer_len) {
                                if &window[pos..pos + footer_len] == footer {
                                    end_offset = Some(start_offset + pos + footer_len);
                                    break;
                                }
                                pos += 1;
                            }
                        }
                    }
                    _ => {}
                }

                if let Some(end) = end_offset {
                    let payload_len = end.saturating_sub(start_offset);
                    if payload_len > 16 && end <= buffer.len() {
                        let carved_data = &buffer[start_offset..end];
                        let (sha256_str, sha1_str) = compute_bytes_hashes(carved_data);

                        // Check for duplicates
                        if seen_hashes.contains(&sha256_str) {
                            duplicates_skipped += 1;
                            offset += header_len;
                            continue;
                        }

                        // Validate recovered artifact
                        let (validation_status, recovery_status) =
                            validate_carved_payload(sig.name, carved_data);

                        if validation_status == "INVALID" {
                            files_invalid += 1;
                        } else {
                            files_recovered += 1;
                            seen_hashes.insert(sha256_str.clone());

                            let artifact_id = Uuid::new_v4().to_string();
                            let safe_filename = format!(
                                "carved_{}_{}.{}",
                                sig.extension,
                                &artifact_id[..8],
                                sig.extension
                            );
                            let target_filepath = output_dir.join(&safe_filename);

                            // Write recovered binary file into isolated carving workspace
                            if fs::write(&target_filepath, carved_data).is_ok() {
                                carved_artifacts.push(FileArtifact {
                                    id: artifact_id,
                                    case_id: case_id.to_string(),
                                    evidence_id: evidence_id.to_string(),
                                    name: safe_filename,
                                    path: target_filepath.to_string_lossy().to_string(),
                                    size_bytes: payload_len as u64,
                                    file_type: sig.name.to_string(),
                                    mime_type: sig.mime_type.to_string(),
                                    offset_bytes: start_offset as u64,
                                    created_at: created_at.clone(),
                                    modified_at: created_at.clone(),
                                    sha256_hash: sha256_str,
                                    sha1_hash: sha1_str,
                                    source_evidence_hash: source_sha256_before.clone(),
                                    is_carved: true,
                                    recovery_status,
                                    validation_status,
                                });
                            }
                        }
                    } else {
                        files_invalid += 1;
                    }
                } else {
                    files_invalid += 1;
                }
            }
            offset += 1;
        }
    }

    // 4. CRITICAL INTEGRITY CONTROL: Calculate source evidence SHA-256 AFTER carving
    let (source_sha256_after, _) = compute_file_hashes(evidence_path)?;

    if source_sha256_before != source_sha256_after {
        return Err(format!(
            "CRITICAL FORENSIC FAILURE: Source evidence SHA-256 changed during carving! Before: {}, After: {}",
            source_sha256_before, source_sha256_after
        ));
    }

    Ok(CarveResult {
        candidates_found,
        files_recovered,
        files_invalid,
        duplicates_skipped,
        carved_artifacts,
        source_sha256_before,
        source_sha256_after,
    })
}

/// Format-specific validation rule
fn validate_carved_payload(format: &str, data: &[u8]) -> (String, String) {
    match format {
        "PDF" => {
            if data.starts_with(b"%PDF-")
                && (data.ends_with(b"%%EOF")
                    || data.ends_with(b"%%EOF\n")
                    || data.ends_with(b"%%EOF\r\n"))
            {
                ("VALID".to_string(), "Carved".to_string())
            } else if data.starts_with(b"%PDF-") {
                ("PARTIAL".to_string(), "Fragmented".to_string())
            } else {
                ("INVALID".to_string(), "Fragmented".to_string())
            }
        }
        "PNG" => {
            let png_magic = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
            if data.len() >= 24 && &data[..8] == png_magic && &data[12..16] == b"IHDR" {
                if data.ends_with(b"IEND")
                    || (data.len() >= 12 && &data[data.len() - 8..data.len() - 4] == b"IEND")
                {
                    ("VALID".to_string(), "Carved".to_string())
                } else {
                    ("PARTIAL".to_string(), "Fragmented".to_string())
                }
            } else {
                ("INVALID".to_string(), "Fragmented".to_string())
            }
        }
        "JPEG" => {
            if data.len() >= 4
                && &data[..3] == &[0xFF, 0xD8, 0xFF]
                && &data[data.len() - 2..] == &[0xFF, 0xD9]
            {
                ("VALID".to_string(), "Carved".to_string())
            } else if data.len() >= 3 && &data[..3] == &[0xFF, 0xD8, 0xFF] {
                ("PARTIAL".to_string(), "Fragmented".to_string())
            } else {
                ("INVALID".to_string(), "Fragmented".to_string())
            }
        }
        _ => ("VALID".to_string(), "Carved".to_string()),
    }
}
