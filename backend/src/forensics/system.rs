use crate::models::SystemArtifact;
use std::fs::File;
use std::io::{BufRead, BufReader};
use uuid::Uuid;

/// Extract real system artifacts from an acquired text log or system event file.
pub async fn extract_system_artifacts(
    file_path: &str,
    case_id: &str,
    evidence_id: &str,
) -> Result<Vec<SystemArtifact>, String> {
    let path_obj = std::path::Path::new(file_path);
    if !path_obj.exists() {
        return Err(format!(
            "System evidence file does not exist: {}",
            file_path
        ));
    }

    let file =
        File::open(path_obj).map_err(|e| format!("Failed to open system evidence file: {}", e))?;
    let reader = BufReader::new(file);

    let extracted_at = chrono::Utc::now().format("%d-%m-%Y %H:%M:%S").to_string();
    let mut artifacts = Vec::new();
    let mut line_count = 0;

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        line_count += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Determine severity and artifact type based on log contents
        let (artifact_type, severity) = if trimmed.to_lowercase().contains("usb")
            || trimmed.to_lowercase().contains("device")
        {
            ("USB Device Registry", "Warning")
        } else if trimmed.to_lowercase().contains("error")
            || trimmed.to_lowercase().contains("failed")
            || trimmed.to_lowercase().contains("critical")
        {
            ("Event Log Failure", "Critical")
        } else if trimmed.to_lowercase().contains("security")
            || trimmed.to_lowercase().contains("logon")
        {
            ("Security Event Log", "Info")
        } else {
            ("System Metadata", "Info")
        };

        artifacts.push(SystemArtifact {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            evidence_id: evidence_id.to_string(),
            artifact_type: artifact_type.to_string(),
            source: path_obj
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            timestamp: extracted_at.clone(),
            description: trimmed.chars().take(200).collect(),
            severity: severity.to_string(),
            extracted_at: extracted_at.clone(),
        });

        if line_count >= 500 {
            break; // Cap max lines per file to prevent excessive memory allocation
        }
    }

    // If file yielded 0 text lines, record a system file intake artifact
    if artifacts.is_empty() {
        let meta = std::fs::metadata(path_obj).ok();
        let file_size = meta.map(|m| m.len()).unwrap_or(0);
        artifacts.push(SystemArtifact {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            evidence_id: evidence_id.to_string(),
            artifact_type: "System Evidence File Intake".to_string(),
            source: path_obj
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            timestamp: extracted_at.clone(),
            description: format!("Acquired system evidence item. Size: {} bytes.", file_size),
            severity: "Info".to_string(),
            extracted_at: extracted_at.clone(),
        });
    }

    Ok(artifacts)
}
