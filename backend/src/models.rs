use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub case_number: String,
    pub title: String,
    pub investigator: String,
    pub status: String, // "Open", "In Progress", "Closed"
    pub created_at: String,
    pub evidence_count: usize,
}

// --- AUTHENTICATION MODELS ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)] // Never serialize password_hash to clients!
    pub password_hash: String,
    pub role: String, // "ADMIN", "INVESTIGATOR", "ANALYST", "VIEWER"
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginDataResponse {
    pub access_token: String,
    pub token_type: String, // "Bearer"
    pub expires_in: u64,    // e.g. 3600
    pub user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub case_id: String,
    pub file_name: String,
    pub file_path: String,
    pub file_size_bytes: u64,
    pub sha256_hash: String,
    pub sha1_hash: String,
    pub acquired_by: String,
    pub acquired_at: String,
    pub write_blocked: bool,
    pub status: String, // "Verified", "Tampered", "Pending"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyLog {
    pub id: String,
    pub case_id: String,
    pub evidence_id: String,
    pub timestamp: String,
    pub action: String, // "Acquisition", "Hash Verification", "Analysis", "Transfer"
    pub custodian: String,
    pub sha256_at_action: String,
    pub integrity_status: String, // "MATCH", "MISMATCH"
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_cases: usize,
    pub total_evidence_items: usize,
    pub reports_generated: usize,
    pub total_storage_gb: f64,
}

#[derive(Debug, Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
    pub investigator: String,
}

#[derive(Debug, Deserialize)]
pub struct AcquireEvidenceRequest {
    pub case_id: String,
    pub file_name: String,
    pub file_path: String,
    pub custodian: String,
    pub write_blocked: bool,
}

#[derive(Debug, Deserialize)]
pub struct VerifyHashRequest {
    pub evidence_id: String,
    pub expected_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyHashResponse {
    pub is_valid: bool,
    pub actual_sha256: String,
    pub expected_sha256: String,
    pub verified_at: String,
}

// --- PHASE 3: ARTIFACT & CARVING MODELS ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileArtifact {
    pub id: String,
    pub case_id: String,
    pub evidence_id: String,
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub file_type: String, // "PDF", "PNG", "JPEG"
    pub mime_type: String, // "application/pdf", "image/png", "image/jpeg"
    pub offset_bytes: u64,
    pub created_at: String,
    pub modified_at: String,
    pub sha256_hash: String,
    pub sha1_hash: String,
    pub source_evidence_hash: String,
    pub is_carved: bool,
    pub recovery_status: String,   // "Carved", "Intact", "Fragmented"
    pub validation_status: String, // "VALID", "INVALID", "PARTIAL"
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileCarveRequest {
    pub case_id: String,
    pub evidence_id: String,
    pub file_types: Option<Vec<String>>,
    pub max_files: Option<usize>,
    pub max_file_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileCarveResponse {
    pub candidates_found: usize,
    pub files_recovered: usize,
    pub files_invalid: usize,
    pub duplicates_skipped: usize,
    pub carved_files: Vec<FileArtifact>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserArtifact {
    pub id: String,
    pub case_id: String,
    pub evidence_id: String,
    pub url: String,
    pub title: String,
    pub visit_time: String,
    pub visit_count: u32,
    pub browser: String,  // "Chrome", "Edge", "Firefox"
    pub category: String, // "History", "Downloads", "Cookies", "Bookmarks"
    pub extracted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemArtifact {
    pub id: String,
    pub case_id: String,
    pub evidence_id: String,
    pub artifact_type: String, // "USB Device", "Registry Key", "Event Log", "Process"
    pub source: String,
    pub timestamp: String,
    pub description: String,
    pub severity: String, // "Info", "Warning", "Critical"
    pub extracted_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExtractBrowserRequest {
    pub case_id: String,
    pub evidence_id: String,
    pub browser: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractBrowserResponse {
    pub browser: String,
    pub artifacts_extracted: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExtractSystemRequest {
    pub case_id: String,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractSystemResponse {
    pub artifacts_extracted: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrowserArtifactQueryParams {
    pub case_id: Option<String>,
    pub evidence_id: Option<String>,
    pub browser: Option<String>,
    pub search: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SystemArtifactQueryParams {
    pub case_id: Option<String>,
    pub evidence_id: Option<String>,
    pub search: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: String,
    pub case_id: String,
    pub timestamp: String,
    pub category: String, // "System", "Filesystem", "USB", "Network", "Browser"
    pub title: String,
    pub description: String,
    pub source_artifact: String,
    pub icon: String,
}

// --- PHASE 4: COURT-READY FORENSIC REPORT MODELS ---

#[derive(Debug, Deserialize)]
pub struct ReportGenerationRequest {
    pub case_id: String,
    pub investigator_name: String,
    pub investigator_id: String,
    pub institution: String,
    pub subject_code: String,
    pub include_custody: bool,
    pub include_carved_files: bool,
    pub include_artifacts: bool,
    pub include_timeline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub report_id: String,
    pub case_id: String,
    pub case_title: String,
    pub investigator_name: String,
    pub investigator_id: String,
    pub institution: String,
    pub subject_code: String,
    pub generated_at: String,
    pub report_sha256_stamp: String, // Cryptographic Immutability Hash Stamp
    pub evidence_items: Vec<EvidenceItem>,
    pub custody_logs: Vec<ChainOfCustodyLog>,
    pub carved_files: Vec<FileArtifact>,
    pub browser_artifacts: Vec<BrowserArtifact>,
    pub system_artifacts: Vec<SystemArtifact>,
    pub timeline_events: Vec<TimelineEvent>,
    pub legal_admissibility_certified: bool,
}

// --- PHASE 5: IOC THREAT CORRELATION & ADVANCED FORENSICS MODELS ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub id: String,
    pub case_id: String,
    pub ioc_type: String, // "IP Address", "File Hash", "Executable Name", "URL Keyword"
    pub indicator_value: String,
    pub matched_source: String,
    pub threat_severity: String, // "Critical", "High", "Medium"
    pub confidence_percentage: u32,
    pub description: String,
    pub matched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatWatchlist {
    pub id: String,
    pub category: String, // "IP Blacklist", "Malware Hashes", "Suspicious Keywords"
    pub value: String,
    pub threat_name: String,
    pub added_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProcessArtifact {
    pub pid: u32,
    pub ppid: u32,
    pub process_name: String,
    pub path: String,
    pub mem_usage_mb: f64,
    pub has_dll_injection: bool,
    pub status: String, // "Running", "Terminated", "Suspicious"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPcapSession {
    pub session_id: String,
    pub protocol: String, // "TCP", "UDP", "DNS", "HTTP"
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub packet_count: u32,
    pub total_bytes: u64,
    pub is_suspicious: bool,
    pub timestamp: String,
}

#[derive(Debug, Deserialize)]
pub struct IocScanRequest {
    pub case_id: String,
    pub custom_keywords: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IocScanResponse {
    pub case_id: String,
    pub total_artifacts_scanned: usize,
    pub match_count: usize,
    pub ioc_matches: Vec<IocMatch>,
    pub scan_timestamp: String,
}
