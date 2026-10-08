import 'dart:convert';
import 'package:http/http.dart' as http;
import 'token_storage.dart';

class ApiService {
  static const String baseUrl = 'http://127.0.0.1:3000/api';

  /// Global callback invoked when an API call receives HTTP 401 Unauthorized
  static void Function()? onUnauthorized;

  /// Private helper to generate headers with JWT Authorization token
  static Future<Map<String, String>> _authHeaders() async {
    final token = await TokenStorage.getToken();
    final headers = <String, String>{
      'Content-Type': 'application/json',
    };
    if (token != null && token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }
    return headers;
  }

  /// Handle status checks for 401 and 403 responses
  static void _checkResponseStatus(http.Response response) {
    if (response.statusCode == 401) {
      TokenStorage.clearSession();
      if (onUnauthorized != null) {
        onUnauthorized!();
      }
    }
  }

  /// Authenticate user via POST /api/auth/login
  static Future<Map<String, dynamic>> login(String username, String password) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'username': username,
          'password': password,
        }),
      );

      final body = json.decode(response.body);

      if (response.statusCode == 200 && body['success'] == true) {
        final data = body['data'];
        final token = data['access_token'] as String;
        final user = data['user'] as Map<String, dynamic>;

        await TokenStorage.saveSession(
          token: token,
          username: user['username'] ?? username,
          role: user['role'] ?? 'INVESTIGATOR',
          userId: user['id'] ?? '',
        );

        return {'success': true, 'data': data};
      } else {
        return {
          'success': false,
          'error': body['message'] ?? 'Invalid username or password',
        };
      }
    } catch (e) {
      return {
        'success': false,
        'error': 'Server unavailable or network error: $e',
      };
    }
  }

  /// Fetch dashboard summary statistics
  static Future<Map<String, dynamic>> fetchStats() async {
    try {
      final headers = await _authHeaders();
      final response = await http.get(Uri.parse('$baseUrl/stats'), headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Backend offline error
    }
    return {
      'total_cases': 0,
      'total_evidence_items': 0,
      'reports_generated': 0,
      'total_storage_gb': 0.0,
      'error': 'Backend offline or unauthorized',
    };
  }

  /// Fetch list of cases
  static Future<List<dynamic>> fetchCases() async {
    try {
      final headers = await _authHeaders();
      final response = await http.get(Uri.parse('$baseUrl/cases'), headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Return empty list on failure
    }
    return [];
  }

  /// Fetch chain of custody logs
  static Future<List<dynamic>> fetchCustodyLogs() async {
    try {
      final headers = await _authHeaders();
      final response = await http.get(Uri.parse('$baseUrl/custody'), headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Return empty list on failure
    }
    return [];
  }

  /// Create a new investigation case
  static Future<Map<String, dynamic>?> createCase(String title, String investigator) async {
    try {
      final headers = await _authHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/cases'),
        headers: headers,
        body: json.encode({
          'title': title,
          'investigator': investigator,
        }),
      );
      _checkResponseStatus(response);
      if (response.statusCode == 200 || response.statusCode == 201) {
        return json.decode(response.body);
      }
      return {'error': 'Server error ${response.statusCode}: ${response.body}'};
    } catch (e) {
      return {'error': 'Connection failed: $e'};
    }
  }

  /// Acquire evidence item
  static Future<Map<String, dynamic>?> acquireEvidence({
    required String caseId,
    required String fileName,
    required String filePath,
    required String custodian,
    required bool writeBlocked,
  }) async {
    try {
      final headers = await _authHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/evidence/acquire'),
        headers: headers,
        body: json.encode({
          'case_id': caseId,
          'file_name': fileName,
          'file_path': filePath,
          'custodian': custodian,
          'write_blocked': writeBlocked,
        }),
      );
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      } else {
        return {'error': response.body};
      }
    } catch (e) {
      return {'error': 'Connection failed: $e'};
    }
  }

  /// Verify evidence hash
  static Future<Map<String, dynamic>?> verifyHash({
    required String evidenceId,
    required String expectedSha256,
  }) async {
    try {
      final headers = await _authHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/evidence/verify'),
        headers: headers,
        body: json.encode({
          'evidence_id': evidenceId,
          'expected_sha256': expectedSha256,
        }),
      );
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
      return {'error': response.body};
    } catch (e) {
      return {'error': 'Connection failed: $e'};
    }
  }

  /// Fetch filesystem artifacts
  static Future<List<dynamic>> fetchFilesystemArtifacts() async {
    try {
      final headers = await _authHeaders();
      final response = await http.get(Uri.parse('$baseUrl/artifacts/files'), headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Empty list on error
    }
    return [];
  }

  /// Carve files from evidence
  static Future<Map<String, dynamic>?> carveFiles({
    required String caseId,
    required String evidenceId,
    List<String>? fileTypes,
  }) async {
    try {
      final headers = await _authHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/artifacts/carve'),
        headers: headers,
        body: json.encode({
          'case_id': caseId,
          'evidence_id': evidenceId,
          'file_types': fileTypes ?? ['pdf', 'png', 'jpeg'],
        }),
      );
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
      return {'error': response.body};
    } catch (e) {
      return {'error': 'Connection failed: $e'};
    }
  }

  /// Download carved binary file
  static Future<http.Response?> downloadCarvedFile(String artifactId) async {
    try {
      final headers = await _authHeaders();
      final response = await http.get(
        Uri.parse('$baseUrl/artifacts/carved/$artifactId/download'),
        headers: headers,
      );
      _checkResponseStatus(response);
      return response;
    } catch (e) {
      return null;
    }
  }

  /// Fetch browser artifacts with optional query parameters
  static Future<List<dynamic>> fetchBrowserArtifacts({
    String? caseId,
    String? browser,
    String? search,
  }) async {
    try {
      final headers = await _authHeaders();
      final queryParams = <String, String>{};
      if (caseId != null && caseId.isNotEmpty) queryParams['case_id'] = caseId;
      if (browser != null && browser.isNotEmpty) queryParams['browser'] = browser;
      if (search != null && search.isNotEmpty) queryParams['search'] = search;

      final uri = Uri.parse('$baseUrl/artifacts/browser').replace(queryParameters: queryParams.isEmpty ? null : queryParams);
      final response = await http.get(uri, headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Empty list on error
    }
    return [];
  }

  /// Trigger real Chrome / Edge browser history extraction from acquired evidence
  static Future<Map<String, dynamic>?> extractBrowserArtifacts({
    required String caseId,
    required String evidenceId,
    String browser = 'Chrome',
  }) async {
    try {
      final headers = await _authHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/artifacts/browser/extract'),
        headers: headers,
        body: json.encode({
          'case_id': caseId,
          'evidence_id': evidenceId,
          'browser': browser,
        }),
      );
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      } else {
        return {'error': response.body};
      }
    } catch (e) {
      return {'error': 'Connection failed: $e'};
    }
  }

  /// Fetch system artifacts with optional query parameters
  static Future<List<dynamic>> fetchSystemArtifacts({
    String? caseId,
    String? search,
  }) async {
    try {
      final headers = await _authHeaders();
      final queryParams = <String, String>{};
      if (caseId != null && caseId.isNotEmpty) queryParams['case_id'] = caseId;
      if (search != null && search.isNotEmpty) queryParams['search'] = search;

      final uri = Uri.parse('$baseUrl/artifacts/system').replace(queryParameters: queryParams.isEmpty ? null : queryParams);
      final response = await http.get(uri, headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Empty list on error
    }
    return [];
  }

  /// Trigger system artifact extraction from acquired evidence
  static Future<Map<String, dynamic>?> extractSystemArtifacts({
    required String caseId,
    required String evidenceId,
  }) async {
    try {
      final headers = await _authHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/artifacts/system/extract'),
        headers: headers,
        body: json.encode({
          'case_id': caseId,
          'evidence_id': evidenceId,
        }),
      );
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      } else {
        return {'error': response.body};
      }
    } catch (e) {
      return {'error': 'Connection failed: $e'};
    }
  }

  /// Fetch timeline events
  static Future<List<dynamic>> fetchTimelineEvents() async {
    try {
      final headers = await _authHeaders();
      final response = await http.get(Uri.parse('$baseUrl/artifacts/timeline'), headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Empty list on error
    }
    return [];
  }

  /// Generate forensic report
  static Future<Map<String, dynamic>?> generateForensicReport({
    required String caseId,
    required String investigatorName,
    required String investigatorId,
    required String institution,
    required String subjectCode,
    bool includeCustody = true,
    bool includeCarvedFiles = true,
    bool includeArtifacts = true,
    bool includeTimeline = true,
  }) async {
    try {
      final headers = await _authHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/reports/generate'),
        headers: headers,
        body: json.encode({
          'case_id': caseId,
          'investigator_name': investigatorName,
          'investigator_id': investigatorId,
          'institution': institution,
          'subject_code': subjectCode,
          'include_custody': includeCustody,
          'include_carved_files': includeCarvedFiles,
          'include_artifacts': includeArtifacts,
          'include_timeline': includeTimeline,
        }),
      );
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
      return {'error': response.body};
    } catch (e) {
      return {'error': 'Connection failed: $e'};
    }
  }

  /// Scan IOC watchlists
  static Future<Map<String, dynamic>?> scanIocWatchlists({
    required String caseId,
    List<String>? customKeywords,
  }) async {
    try {
      final headers = await _authHeaders();
      final response = await http.post(
        Uri.parse('$baseUrl/ioc/scan'),
        headers: headers,
        body: json.encode({
          'case_id': caseId,
          'custom_keywords': customKeywords ?? [],
        }),
      );
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
      return {'error': response.body};
    } catch (e) {
      return {'error': 'Connection failed: $e'};
    }
  }

  /// Fetch memory processes
  static Future<List<dynamic>> fetchMemoryProcesses() async {
    try {
      final headers = await _authHeaders();
      final response = await http.get(Uri.parse('$baseUrl/forensics/memory'), headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Empty list on error
    }
    return [];
  }

  /// Fetch network sessions
  static Future<List<dynamic>> fetchNetworkSessions() async {
    try {
      final headers = await _authHeaders();
      final response = await http.get(Uri.parse('$baseUrl/forensics/network'), headers: headers);
      _checkResponseStatus(response);
      if (response.statusCode == 200) {
        return json.decode(response.body);
      }
    } catch (e) {
      // Empty list on error
    }
    return [];
  }
}
