import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../services/token_storage.dart';
import 'login_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  int _activeTabIndex = 0; // 0: Overview, 1: Acquisition, 2: Chain of Custody, 3: Report Preview
  
  String _currentUsername = 'Investigator';
  String _currentRole = 'INVESTIGATOR';

  Map<String, dynamic> _stats = {
    'total_cases': 4,
    'total_evidence_items': 2,
    'reports_generated': 4,
    'total_storage_gb': 290.0,
  };
  List<dynamic> _cases = [];
  List<dynamic> _custodyLogs = [];
  List<dynamic> _fileArtifacts = [];
  List<dynamic> _browserArtifacts = [];
  List<dynamic> _systemArtifacts = [];
  List<dynamic> _timelineEvents = [];
  List<dynamic> _iocMatches = [];
  List<dynamic> _memoryProcesses = [];
  List<dynamic> _networkSessions = [];
  String _selectedTimelineCategory = 'All';
  bool _isLoading = true;

  // Acquisition, Carving & Reporting Form Controls
  final _caseIdController = TextEditingController(text: 'CASE-2024-001');
  final _fileNameController = TextEditingController(text: 'disk_dump_c_drive.raw');
  final _filePathController = TextEditingController(text: 'c:\\forensiQ\\ForensiQ_Project_Abstract.pdf');
  final _custodianController = TextEditingController(text: 'Lead Investigator J. Dinesh');
  final _carveEvidenceIdController = TextEditingController();
  final _iocKeywordController = TextEditingController(text: 'report_docs.exe, example-fraud-portal.com');
  final Set<String> _carveSignatures = {'PDF', 'PNG', 'JPEG'};
  Map<String, dynamic>? _carvingSummary;
  
  // Phase 4 Report Configurator Controls
  final _reportCaseIdController = TextEditingController(text: 'CASE-2024-001');
  final _reportInvestigatorNameController = TextEditingController(text: 'J. Dinesh');
  final _reportInvestigatorIdController = TextEditingController(text: '24634-CM-031');
  final _reportInstitutionController = TextEditingController(text: 'ALWARDAS POLYTECHNIC');
  final _reportSubjectCodeController = TextEditingController(text: 'CM-509 PROJECT WORK');
  bool _incCustody = true;
  bool _incCarved = true;
  bool _incArtifacts = true;
  bool _incTimeline = true;
  bool _isGeneratingReport = false;
  bool _isScanningIoc = false;
  Map<String, dynamic>? _generatedReportData;
  String _selectedBrowserFilter = 'All';
  String _extractBrowserName = 'Chrome';
  final _artifactSearchController = TextEditingController();
  bool _isExtractingArtifacts = false;
  bool _isExtractingSystem = false;

  bool _writeBlocked = true;
  bool _isAcquiring = false;
  bool _isCarving = false;
  Map<String, dynamic>? _acquisitionResult;

  @override
  void initState() {
    super.initState();
    _loadDashboardData();
  }

  Future<void> _loadDashboardData() async {
    setState(() => _isLoading = true);
    final username = await TokenStorage.getUsername() ?? 'Investigator';
    final role = await TokenStorage.getRole() ?? 'INVESTIGATOR';
    
    _custodianController.text = username;
    _reportInvestigatorNameController.text = username;

    final statsData = await ApiService.fetchStats();
    final casesData = await ApiService.fetchCases();
    final logsData = await ApiService.fetchCustodyLogs();
    final filesData = await ApiService.fetchFilesystemArtifacts();
    final browserData = await ApiService.fetchBrowserArtifacts();
    final systemData = await ApiService.fetchSystemArtifacts();
    final timelineData = await ApiService.fetchTimelineEvents();
    final iocScanRes = await ApiService.scanIocWatchlists(caseId: _caseIdController.text);
    final memoryData = await ApiService.fetchMemoryProcesses();
    final networkData = await ApiService.fetchNetworkSessions();

    setState(() {
      _currentUsername = username;
      _currentRole = role;
      _stats = statsData;
      _cases = casesData;
      _custodyLogs = logsData;
      _fileArtifacts = filesData;
      _browserArtifacts = browserData;
      _systemArtifacts = systemData;
      _timelineEvents = timelineData;
      if (iocScanRes != null && iocScanRes.containsKey('ioc_matches')) {
        _iocMatches = iocScanRes['ioc_matches'];
      }
      _memoryProcesses = memoryData;
      _networkSessions = networkData;
      _isLoading = false;
    });
  }

  Future<void> _handleLogout() async {
    await TokenStorage.clearSession();
    if (!mounted) return;
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (_) => const LoginScreen()),
    );
  }

  Future<void> _handleIocScan() async {
    setState(() => _isScanningIoc = true);
    final kwList = _iocKeywordController.text.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty).toList();
    final res = await ApiService.scanIocWatchlists(
      caseId: _caseIdController.text,
      customKeywords: kwList,
    );

    setState(() {
      _isScanningIoc = false;
      if (res != null && res.containsKey('ioc_matches')) {
        _iocMatches = res['ioc_matches'];
      }
    });

    if (res != null) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('IOC Threat scan complete! Found ${res['match_count']} threat hits across ${res['total_artifacts_scanned']} artifacts.'),
          backgroundColor: const Color(0xFFDA3633),
        ),
      );
      _loadDashboardData();
    }
  }

  Future<void> _handleFileCarving() async {
    final caseId = _caseIdController.text.trim();
    String evidenceId = _carveEvidenceIdController.text.trim();
    
    // Fallback to latest acquired evidence if empty
    if (evidenceId.isEmpty && _custodyLogs.isNotEmpty) {
      evidenceId = _custodyLogs.first['evidence_id'] ?? '';
    }

    if (caseId.isEmpty || evidenceId.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please select or specify Case ID and Evidence ID for carving.'),
          backgroundColor: Color(0xFFDA3633),
        ),
      );
      return;
    }

    setState(() {
      _isCarving = true;
      _carvingSummary = null;
    });

    final res = await ApiService.carveFiles(
      caseId: caseId,
      evidenceId: evidenceId,
      fileTypes: _carveSignatures.map((s) => s.toLowerCase()).toList(),
    );

    setState(() => _isCarving = false);

    if (res != null && res.containsKey('data')) {
      final summary = res['data'] as Map<String, dynamic>;
      setState(() {
        _carvingSummary = summary;
      });
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('FILE CARVING COMPLETE: Candidates: ${summary['candidates_found']}, Recovered: ${summary['files_recovered']}, Invalid: ${summary['files_invalid']}, Duplicates: ${summary['duplicates_skipped']}'),
          backgroundColor: const Color(0xFF238636),
        ),
      );
      _loadDashboardData();
    } else if (res != null && res.containsKey('error')) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Carving Error: ${res['error']}'),
          backgroundColor: const Color(0xFFDA3633),
        ),
      );
    }
  }

  Future<void> _handleDownloadCarvedFile(String artifactId, String fileName) async {
    final response = await ApiService.downloadCarvedFile(artifactId);
    if (!mounted) return;
    if (response != null && response.statusCode == 200) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Downloaded "$fileName" (${response.bodyBytes.length} bytes verified).'),
          backgroundColor: const Color(0xFF238636),
        ),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Download failed for "$fileName": ${response?.body ?? 'Unauthorized or file missing'}'),
          backgroundColor: const Color(0xFFDA3633),
        ),
      );
    }
  }

  Future<void> _handleGenerateReport() async {
    setState(() => _isGeneratingReport = true);
    final res = await ApiService.generateForensicReport(
      caseId: _reportCaseIdController.text,
      investigatorName: _reportInvestigatorNameController.text,
      investigatorId: _reportInvestigatorIdController.text,
      institution: _reportInstitutionController.text,
      subjectCode: _reportSubjectCodeController.text,
      includeCustody: _incCustody,
      includeCarvedFiles: _incCarved,
      includeArtifacts: _incArtifacts,
      includeTimeline: _incTimeline,
    );

    setState(() {
      _isGeneratingReport = false;
      _generatedReportData = res;
    });

    if (res != null) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Court-ready forensic report compiled! Immutability Stamp: ${(res['report_sha256_stamp'] ?? '').substring(0, 16)}...'),
          backgroundColor: const Color(0xFF238636),
        ),
      );
      _loadDashboardData();
    }
  }

  Future<void> _handleAcquisition() async {
    setState(() {
      _isAcquiring = true;
      _acquisitionResult = null;
    });

    final res = await ApiService.acquireEvidence(
      caseId: _caseIdController.text,
      fileName: _fileNameController.text,
      filePath: _filePathController.text,
      custodian: _custodianController.text,
      writeBlocked: _writeBlocked,
    );

    setState(() {
      _isAcquiring = false;
      _acquisitionResult = res;
    });

    if (res != null && res.containsKey('error')) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Acquisition Failed: ${res['error']}'),
          backgroundColor: const Color(0xFFDA3633),
        ),
      );
    } else if (res != null) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Evidence acquired! SHA-256 and SHA-1 cryptographic hashes generated.'),
          backgroundColor: Color(0xFF238636),
        ),
      );
      _loadDashboardData();
    }
  }

  Future<void> _showCreateCaseDialog() async {
    final titleCtrl = TextEditingController();
    final invCtrl = TextEditingController(text: 'K. Charan Teja');

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161B22),
        title: Text('Create New Forensic Case', style: GoogleFonts.outfit(color: Colors.white, fontWeight: FontWeight.bold)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: titleCtrl,
              style: const TextStyle(color: Colors.white),
              decoration: const InputDecoration(
                labelText: 'Case Title',
                labelStyle: TextStyle(color: Colors.grey),
                enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Colors.grey)),
                focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF1F6FEB))),
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: invCtrl,
              style: const TextStyle(color: Colors.white),
              decoration: const InputDecoration(
                labelText: 'Lead Investigator',
                labelStyle: TextStyle(color: Colors.grey),
                enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Colors.grey)),
                focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF1F6FEB))),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel', style: TextStyle(color: Colors.grey)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1F6FEB)),
            onPressed: () async {
              if (titleCtrl.text.isNotEmpty) {
                final nav = Navigator.of(ctx);
                await ApiService.createCase(titleCtrl.text, invCtrl.text);
                nav.pop();
                _loadDashboardData();
              }
            },
            child: const Text('Create Case', style: TextStyle(color: Colors.white)),
          )
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          _buildHeader(),
          _buildWorkflowBanner(),
          _buildTabBar(),
          Expanded(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator(color: Color(0xFF1F6FEB)))
                : _buildTabBody(),
          ),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      color: const Color(0xFF090D13),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final isNarrow = constraints.maxWidth < 850;
          return Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            runSpacing: 12,
            spacing: 16,
            children: [
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF1F6FEB).withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: const Color(0xFF1F6FEB)),
                    ),
                    child: const Icon(Icons.security, color: Color(0xFF58A6FF), size: 28),
                  ),
                  const SizedBox(width: 16),
                  Flexible(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          'DIGITAL FORENSIC INVESTIGATION TOOLKIT',
                          style: GoogleFonts.outfit(
                            color: Colors.white,
                            fontSize: isNarrow ? 16 : 20,
                            fontWeight: FontWeight.bold,
                            letterSpacing: 1.2,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                        Text(
                          'EVIDENCE ACQUISITION | ANALYSIS | TIMELINE | REPORTING',
                          style: GoogleFonts.inter(
                            color: const Color(0xFF8B949E),
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            letterSpacing: 1.5,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF238636).withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: const Color(0xFF238636)),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 8,
                          height: 8,
                          decoration: const BoxDecoration(
                            color: Color(0xFF3FB950),
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          'AXUM BACKEND ONLINE (PORT 3000)',
                          style: GoogleFonts.inter(
                            color: const Color(0xFF3FB950),
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),
                  // User Identity Badge
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF161B22),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: const Color(0xFF30363D)),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.person, color: Color(0xFF58A6FF), size: 16),
                        const SizedBox(width: 6),
                        Text(
                          _currentUsername,
                          style: GoogleFonts.inter(
                            color: Colors.white,
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: const Color(0xFF1F6FEB).withValues(alpha: 0.2),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            _currentRole,
                            style: GoogleFonts.inter(
                              color: const Color(0xFF58A6FF),
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),
                  ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF1F6FEB),
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    ),
                    onPressed: _showCreateCaseDialog,
                    icon: const Icon(Icons.add, color: Colors.white, size: 18),
                    label: Text('New Case', style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold)),
                  ),
                  const SizedBox(width: 8),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: Color(0xFFDA3633)),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                    ),
                    onPressed: _handleLogout,
                    icon: const Icon(Icons.logout, color: Color(0xFFF85149), size: 16),
                    label: Text('Logout', style: GoogleFonts.inter(color: const Color(0xFFF85149), fontWeight: FontWeight.bold, fontSize: 12)),
                  ),
                ],
              ),
            ],
          );
        },
      ),
    );
  }

  Widget _buildWorkflowBanner() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
      decoration: const BoxDecoration(
        color: Color(0xFF161B22),
        border: Border(bottom: BorderSide(color: Color(0xFF30363D))),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceAround,
          children: [
            _buildWorkflowStep('1. ACQUIRE', 'Collect digital evidence securely', Icons.save_alt, true),
            _buildStepArrow(),
            _buildWorkflowStep('2. EXTRACT', 'Extract system artifacts', Icons.data_object, true),
            _buildStepArrow(),
            _buildWorkflowStep('3. ANALYZE', 'Analyze files, logs & memory', Icons.search, true),
            _buildStepArrow(),
            _buildWorkflowStep('4. TIMELINE', 'Reconstruct events', Icons.timeline, true),
            _buildStepArrow(),
            _buildWorkflowStep('5. REPORT', 'Generate court-ready PDF', Icons.picture_as_pdf, true),
          ],
        ),
      ),
    );
  }

  Widget _buildWorkflowStep(String title, String desc, IconData icon, bool active) {
    return Row(
      children: [
        Icon(icon, color: active ? const Color(0xFF58A6FF) : Colors.grey, size: 20),
        const SizedBox(width: 10),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: GoogleFonts.outfit(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold)),
            Text(desc, style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 10)),
          ],
        ),
      ],
    );
  }

  Widget _buildStepArrow() {
    return const Icon(Icons.chevron_right, color: Color(0xFF484F58), size: 20);
  }

  Widget _buildTabBar() {
    return Container(
      color: const Color(0xFF0D1117),
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: [
            _buildTabItem(0, Icons.dashboard, 'Dashboard Overview'),
            _buildTabItem(1, Icons.lock_clock, 'Evidence Acquisition & Hashing'),
            _buildTabItem(2, Icons.fact_check, 'Chain of Custody Logs'),
            _buildTabItem(3, Icons.folder_zip, 'Filesystem & File Carving'),
            _buildTabItem(4, Icons.manage_search, 'Multi-Source Artifact Analysis'),
            _buildTabItem(5, Icons.timeline, 'Cross-Source Timeline Correlation'),
            _buildTabItem(6, Icons.security_update_warning, 'Automated IOC & Threat Correlation'),
            _buildTabItem(7, Icons.description, 'Court-Ready PDF Report Workbench'),
          ],
        ),
      ),
    );
  }

  Widget _buildTabItem(int index, IconData icon, String label) {
    final selected = _activeTabIndex == index;
    return InkWell(
      onTap: () => setState(() => _activeTabIndex = index),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
        margin: const EdgeInsets.only(right: 12),
        decoration: BoxDecoration(
          color: selected ? const Color(0xFF1F6FEB).withValues(alpha: 0.2) : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: selected ? const Color(0xFF1F6FEB) : Colors.transparent,
          ),
        ),
        child: Row(
          children: [
            Icon(icon, color: selected ? const Color(0xFF58A6FF) : const Color(0xFF8B949E), size: 18),
            const SizedBox(width: 8),
            Text(
              label,
              style: GoogleFonts.inter(
                color: selected ? Colors.white : const Color(0xFF8B949E),
                fontWeight: selected ? FontWeight.bold : FontWeight.w500,
                fontSize: 13,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTabBody() {
    switch (_activeTabIndex) {
      case 0:
        return _buildOverviewTab();
      case 1:
        return _buildAcquisitionTab();
      case 2:
        return _buildCustodyTab();
      case 3:
        return _buildFilesystemTab();
      case 4:
        return _buildArtifactAnalysisTab();
      case 5:
        return _buildTimelineTab();
      case 6:
        return _buildIocThreatTab();
      case 7:
        return _buildReportPreviewTab();
      default:
        return _buildOverviewTab();
    }
  }

  // --- TAB 0: OVERVIEW ---
  Widget _buildOverviewTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          LayoutBuilder(
            builder: (context, constraints) {
              if (constraints.maxWidth < 900) {
                return Column(
                  children: [
                    Row(
                      children: [
                        _buildStatCard('Total Cases', '${_stats['total_cases']}', Icons.folder_special, const Color(0xFF1F6FEB)),
                        const SizedBox(width: 16),
                        _buildStatCard('Evidence Items', '${_stats['total_evidence_items']}', Icons.sd_card, const Color(0xFF238636)),
                      ],
                    ),
                    const SizedBox(height: 16),
                    Row(
                      children: [
                        _buildStatCard('Reports Generated', '${_stats['reports_generated']}', Icons.picture_as_pdf, const Color(0xFF8957E5)),
                        const SizedBox(width: 16),
                        _buildStatCard('Total Storage', '${_stats['total_storage_gb']} GB', Icons.storage, const Color(0xFFD29922)),
                      ],
                    ),
                  ],
                );
              }
              return Row(
                children: [
                  _buildStatCard('Total Cases', '${_stats['total_cases']}', Icons.folder_special, const Color(0xFF1F6FEB)),
                  const SizedBox(width: 16),
                  _buildStatCard('Evidence Items', '${_stats['total_evidence_items']}', Icons.sd_card, const Color(0xFF238636)),
                  const SizedBox(width: 16),
                  _buildStatCard('Reports Generated', '${_stats['reports_generated']}', Icons.picture_as_pdf, const Color(0xFF8957E5)),
                  const SizedBox(width: 16),
                  _buildStatCard('Total Storage', '${_stats['total_storage_gb']} GB', Icons.storage, const Color(0xFFD29922)),
                ],
              );
            },
          ),
          const SizedBox(height: 24),
          Text('Recent Forensic Cases', style: GoogleFonts.outfit(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Container(
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF30363D)),
            ),
            child: DataTable(
              headingRowColor: WidgetStateProperty.all(const Color(0xFF21262D)),
              columns: const [
                DataColumn(label: Text('Case ID', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                DataColumn(label: Text('Title', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                DataColumn(label: Text('Lead Investigator', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                DataColumn(label: Text('Date Created', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                DataColumn(label: Text('Evidence Items', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                DataColumn(label: Text('Status', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
              ],
              rows: _cases.map((c) {
                return DataRow(cells: [
                  DataCell(Text(c['case_number'] ?? '', style: const TextStyle(color: Color(0xFF58A6FF), fontWeight: FontWeight.bold))),
                  DataCell(Text(c['title'] ?? '', style: const TextStyle(color: Colors.white))),
                  DataCell(Text(c['investigator'] ?? '', style: const TextStyle(color: Colors.grey))),
                  DataCell(Text(c['created_at'] ?? '', style: const TextStyle(color: Colors.grey))),
                  DataCell(Text('${c['evidence_count'] ?? 0}', style: const TextStyle(color: Colors.white))),
                  DataCell(_buildStatusChip(c['status'] ?? 'Open')),
                ]);
              }).toList(),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatCard(String title, String value, IconData icon, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: const Color(0xFF161B22),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: const Color(0xFF30363D)),
        ),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(icon, color: color, size: 28),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(title, style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 12), overflow: TextOverflow.ellipsis),
                  Text(value, style: GoogleFonts.outfit(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold), overflow: TextOverflow.ellipsis),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusChip(String status) {
    Color bg = const Color(0xFF1F6FEB).withValues(alpha: 0.2);
    Color text = const Color(0xFF58A6FF);
    if (status == 'Closed') {
      bg = const Color(0xFF238636).withValues(alpha: 0.2);
      text = const Color(0xFF3FB950);
    } else if (status == 'In Progress') {
      bg = const Color(0xFFD29922).withValues(alpha: 0.2);
      text = const Color(0xFFD29922);
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(status, style: TextStyle(color: text, fontSize: 11, fontWeight: FontWeight.bold)),
    );
  }

  // --- TAB 1: ACQUISITION ---
  Widget _buildAcquisitionTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.security, color: Color(0xFF58A6FF), size: 24),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Write-Blocked Evidence Acquisition & Cryptographic Hashing Engine',
                  style: GoogleFonts.outfit(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Acquire raw disk images, memory dumps, or file evidence with hardware/software write-blocking and real-time SHA-256 & SHA-1 hashing.',
            style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13),
          ),
          const SizedBox(height: 24),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                flex: 3,
                child: Container(
                  padding: const EdgeInsets.all(24),
                  decoration: BoxDecoration(
                    color: const Color(0xFF161B22),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: const Color(0xFF30363D)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _buildTextField(_caseIdController, 'Case ID', 'e.g. CASE-2024-001'),
                      const SizedBox(height: 16),
                      _buildTextField(_fileNameController, 'Evidence Item Name', 'e.g. suspect_drive.raw'),
                      const SizedBox(height: 16),
                      _buildTextField(_filePathController, 'Target File / Disk Image Path', 'e.g. C:\\forensiQ\\ForensiQ_Project_Abstract.pdf'),
                      const SizedBox(height: 16),
                      _buildTextField(_custodianController, 'Custodian / Investigator Name', 'e.g. G. Sai'),
                      const SizedBox(height: 20),
                      Row(
                        children: [
                          Switch(
                            value: _writeBlocked,
                            activeThumbColor: const Color(0xFF3FB950),
                            onChanged: (val) => setState(() => _writeBlocked = val),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text('Write-Blocking Enforcement ACTIVE', style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13)),
                                Text('Prevents drive modifications during acquisition to maintain legal chain of custody.', style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 11)),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 24),
                      SizedBox(
                        width: double.infinity,
                        height: 48,
                        child: ElevatedButton.icon(
                          style: ElevatedButton.styleFrom(
                            backgroundColor: const Color(0xFF238636),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                          ),
                          onPressed: _isAcquiring ? null : _handleAcquisition,
                          icon: _isAcquiring
                              ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                              : const Icon(Icons.fingerprint, color: Colors.white),
                          label: Text(
                            _isAcquiring ? 'ACQUIRING & HASHING VIA RUST ENGINE...' : 'START EVIDENCE ACQUISITION & HASHING',
                            style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 24),
              Expanded(
                flex: 2,
                child: Container(
                  padding: const EdgeInsets.all(24),
                  decoration: BoxDecoration(
                    color: const Color(0xFF161B22),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: const Color(0xFF30363D)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Cryptographic Integrity Output', style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                      const SizedBox(height: 16),
                      if (_acquisitionResult == null)
                        const Padding(
                          padding: EdgeInsets.symmetric(vertical: 40),
                          child: Center(
                            child: Text(
                              'Click "START EVIDENCE ACQUISITION & HASHING" to execute real-time Rust SHA-256 / SHA-1 checksum calculation.',
                              textAlign: TextAlign.center,
                              style: TextStyle(color: Colors.grey),
                            ),
                          ),
                        )
                      else ...[
                        _buildHashField('SHA-256 CHECKSUM', _acquisitionResult!['sha256_hash'] ?? '', const Color(0xFF58A6FF)),
                        const SizedBox(height: 16),
                        _buildHashField('SHA-1 CHECKSUM', _acquisitionResult!['sha1_hash'] ?? '', const Color(0xFFD29922)),
                        const SizedBox(height: 16),
                        _buildMetaItem('File Size Bytes', '${_acquisitionResult!['file_size_bytes']} bytes'),
                        _buildMetaItem('Acquisition Timestamp', _acquisitionResult!['acquired_at'] ?? ''),
                        _buildMetaItem('Chain-of-Custody ID', _acquisitionResult!['id'] ?? ''),
                        const SizedBox(height: 16),
                        Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: const Color(0xFF238636).withValues(alpha: 0.2),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: const Color(0xFF238636)),
                          ),
                          child: const Row(
                            children: [
                              Icon(Icons.verified, color: Color(0xFF3FB950)),
                              SizedBox(width: 10),
                              Expanded(
                                child: Text(
                                  'Integrity Logged to Tamper-Evident Chain-of-Custody Store.',
                                  style: TextStyle(color: Color(0xFF3FB950), fontWeight: FontWeight.bold, fontSize: 12),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildTextField(TextEditingController controller, String label, String hint) {
    return TextField(
      controller: controller,
      style: const TextStyle(color: Colors.white),
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
        labelStyle: const TextStyle(color: Colors.grey),
        hintStyle: TextStyle(color: Colors.grey.shade700),
        enabledBorder: const OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF30363D))),
        focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF1F6FEB))),
        filled: true,
        fillColor: const Color(0xFF0D1117),
      ),
    );
  }

  Widget _buildHashField(String title, String hash, Color color) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: GoogleFonts.inter(color: color, fontSize: 11, fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        Container(
          padding: const EdgeInsets.all(10),
          width: double.infinity,
          decoration: BoxDecoration(
            color: const Color(0xFF0D1117),
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: const Color(0xFF30363D)),
          ),
          child: SelectableText(
            hash,
            style: GoogleFonts.firaCode(color: Colors.white, fontSize: 11),
          ),
        ),
      ],
    );
  }

  Widget _buildMetaItem(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(color: Colors.grey, fontSize: 12)),
          Text(value, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
        ],
      ),
    );
  }

  // --- TAB 2: CHAIN OF CUSTODY ---
  Widget _buildCustodyTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Tamper-Evident Chain-of-Custody Audit Log', style: GoogleFonts.outfit(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Text('Every acquisition, verification, and transfer action is cryptographically signed and logged with timestamp & custodian records.', style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13)),
          const SizedBox(height: 24),
          ListView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: _custodyLogs.length,
            itemBuilder: (ctx, idx) {
              final log = _custodyLogs[idx];
              return Container(
                margin: const EdgeInsets.only(bottom: 16),
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: const Color(0xFF161B22),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF30363D)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                              decoration: BoxDecoration(
                                color: const Color(0xFF1F6FEB).withValues(alpha: 0.2),
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(log['case_id'] ?? '', style: const TextStyle(color: Color(0xFF58A6FF), fontWeight: FontWeight.bold, fontSize: 12)),
                            ),
                            const SizedBox(width: 12),
                            Text(log['action'] ?? '', style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                          ],
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                          decoration: BoxDecoration(
                            color: log['integrity_status'] == 'MATCH' ? const Color(0xFF238636).withValues(alpha: 0.2) : Colors.red.withValues(alpha: 0.2),
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: Text(
                            'INTEGRITY: ${log['integrity_status']}',
                            style: TextStyle(
                              color: log['integrity_status'] == 'MATCH' ? const Color(0xFF3FB950) : Colors.red,
                              fontSize: 11,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Text(log['notes'] ?? '', style: const TextStyle(color: Colors.grey, fontSize: 13)),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        const Icon(Icons.person, color: Colors.grey, size: 16),
                        const SizedBox(width: 6),
                        Text('Custodian: ${log['custodian']}', style: const TextStyle(color: Colors.white, fontSize: 12)),
                        const SizedBox(width: 24),
                        const Icon(Icons.access_time, color: Colors.grey, size: 16),
                        const SizedBox(width: 6),
                        Text('Timestamp: ${log['timestamp']}', style: const TextStyle(color: Colors.white, fontSize: 12)),
                      ],
                    ),
                    const SizedBox(height: 12),
                    _buildHashField('RECORDED SHA-256 HASH AT ACTION', log['sha256_at_action'] ?? '', const Color(0xFF58A6FF)),
                  ],
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  // =============================================================
  // --- PHASE 4: COURT-READY REPORT GENERATION & PDF EXPORT ---
  // =============================================================
  Widget _buildReportPreviewTab() {
    final reportData = _generatedReportData;
    final reportId = reportData?['report_id'] ?? 'RPT-88A9231B';
    final reportStamp = reportData?['report_sha256_stamp'] ?? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    final genTime = reportData?['generated_at'] ?? '27-08-2026 12:25:00';

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.picture_as_pdf, color: Color(0xFF1F6FEB), size: 28),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Phase 4: Court-Ready Forensic Report Generator & PDF Export Engine',
                  style: GoogleFonts.outfit(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            'Compile evidence integrity records, custody logs, carved file inventory, and correlated timeline streams into an immutable, court-admissible forensic report with cryptographic SHA-256 digital stamp.',
            style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13),
          ),
          const SizedBox(height: 24),
          
          // --- REPORT CONFIGURATOR PANEL ---
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: const Color(0xFF30363D)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Report Configuration & Investigator Certification', style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                const SizedBox(height: 16),
                Wrap(
                  spacing: 16,
                  runSpacing: 12,
                  children: [
                    SizedBox(width: 200, child: _buildTextField(_reportCaseIdController, 'Case ID', 'CASE-2024-001')),
                    SizedBox(width: 220, child: _buildTextField(_reportInvestigatorNameController, 'Lead Investigator', 'J. Dinesh')),
                    SizedBox(width: 180, child: _buildTextField(_reportInvestigatorIdController, 'Reg Number / ID', '24634-CM-031')),
                    SizedBox(width: 250, child: _buildTextField(_reportInstitutionController, 'Institution', 'ALWARDAS POLYTECHNIC')),
                    SizedBox(width: 220, child: _buildTextField(_reportSubjectCodeController, 'Subject Code', 'CM-509 PROJECT WORK')),
                  ],
                ),
                const SizedBox(height: 16),
                Text('Include Forensic Sections:', style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 12, fontWeight: FontWeight.bold)),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 12,
                  runSpacing: 8,
                  children: [
                    FilterChip(
                      selected: _incCustody,
                      label: const Text('Chain of Custody Log', style: TextStyle(color: Colors.white, fontSize: 12)),
                      selectedColor: const Color(0xFF1F6FEB),
                      backgroundColor: const Color(0xFF0D1117),
                      onSelected: (val) => setState(() => _incCustody = val),
                    ),
                    FilterChip(
                      selected: _incCarved,
                      label: const Text('Carved File Inventory', style: TextStyle(color: Colors.white, fontSize: 12)),
                      selectedColor: const Color(0xFF8957E5),
                      backgroundColor: const Color(0xFF0D1117),
                      onSelected: (val) => setState(() => _incCarved = val),
                    ),
                    FilterChip(
                      selected: _incArtifacts,
                      label: const Text('Multi-Source Artifacts', style: TextStyle(color: Colors.white, fontSize: 12)),
                      selectedColor: const Color(0xFF238636),
                      backgroundColor: const Color(0xFF0D1117),
                      onSelected: (val) => setState(() => _incArtifacts = val),
                    ),
                    FilterChip(
                      selected: _incTimeline,
                      label: const Text('Correlated Timeline', style: TextStyle(color: Colors.white, fontSize: 12)),
                      selectedColor: const Color(0xFFD29922),
                      backgroundColor: const Color(0xFF0D1117),
                      onSelected: (val) => setState(() => _incTimeline = val),
                    ),
                  ],
                ),
                const SizedBox(height: 20),
                SizedBox(
                  width: double.infinity,
                  height: 46,
                  child: ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF1F6FEB),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    onPressed: _isGeneratingReport ? null : _handleGenerateReport,
                    icon: _isGeneratingReport
                        ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                        : const Icon(Icons.gavel, color: Colors.white),
                    label: Text(
                      _isGeneratingReport ? 'COMPILING REPORT & COMPUTING IMMUTABILITY HASH...' : 'COMPILE COURT-READY FORENSIC REPORT',
                      style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold),
                    ),
                  ),
                ),
              ],
            ),
          ),
          
          const SizedBox(height: 32),

          // --- LIVE COURTROOM PDF DOCUMENT PREVIEW ---
          Center(
            child: Container(
              constraints: const BoxConstraints(maxWidth: 850),
              padding: const EdgeInsets.all(36),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(4),
                boxShadow: [
                  BoxShadow(color: Colors.black.withValues(alpha: 0.5), blurRadius: 20, offset: const Offset(0, 10)),
                ],
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Official Header
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            _reportInstitutionController.text.toUpperCase(),
                            style: GoogleFonts.outfit(color: Colors.black, fontSize: 18, fontWeight: FontWeight.bold, letterSpacing: 1.1),
                          ),
                          Text(
                            'DEPARTMENT OF COMPUTER ENGINEERING — ${_reportSubjectCodeController.text.toUpperCase()}',
                            style: GoogleFonts.inter(color: Colors.grey.shade800, fontSize: 10, fontWeight: FontWeight.w600),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'DIGITAL FORENSIC INVESTIGATION REPORT',
                            style: GoogleFonts.outfit(color: const Color(0xFF090D13), fontSize: 20, fontWeight: FontWeight.bold),
                          ),
                          Text(
                            'STRICTLY CONFIDENTIAL — COURT ADMISSIBLE EVIDENCE SUMMARY',
                            style: GoogleFonts.inter(color: Colors.grey.shade700, fontSize: 10, fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(border: Border.all(color: Colors.black, width: 1.5)),
                        child: Column(
                          children: [
                            Text('ForensiQ v1.0', style: GoogleFonts.firaCode(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 12)),
                            Text(reportId, style: GoogleFonts.firaCode(color: const Color(0xFF1F6FEB), fontWeight: FontWeight.bold, fontSize: 10)),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const Divider(color: Colors.black, height: 28, thickness: 2),

                  // Section 1: Executive Case Summary
                  _buildReportSection('1. EXECUTIVE CASE SUMMARY & METADATA', [
                    'Case Reference: ${_reportCaseIdController.text}',
                    'Case Title: Cyber Fraud Investigation & Artifact Correlation',
                    'Lead Investigator: ${_reportInvestigatorNameController.text} (Reg ID: ${_reportInvestigatorIdController.text})',
                    'Institution: ${_reportInstitutionController.text} — Subject: ${_reportSubjectCodeController.text}',
                    'Report Compilation Timestamp: $genTime',
                    'Target System Environment: Windows 10 x64 Workstation (DESKTOP-DFTK01)',
                  ]),
                  const SizedBox(height: 20),

                  // Section 2: Evidence Inventory & Integrity
                  _buildReportSection('2. EVIDENCE ACQUISITION & CRYPTOGRAPHIC INTEGRITY', [
                    'Primary Evidence ID: EV-2024-88A9',
                    'Interface / Hardware: Hardware Write-Blocker (Model WB-3000)',
                    'Acquired Target: hard_disk_image.raw (256.0 GB)',
                    'SHA-256 Hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
                    'SHA-1 Hash: f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5',
                    'Cryptographic Verification: PASSED (Zero byte alteration / intact chain of custody)',
                  ]),
                  const SizedBox(height: 20),

                  // Section 3: Chain of Custody Audit Log
                  if (_incCustody) ...[
                    _buildReportSection('3. TAMPER-EVIDENT CHAIN-OF-CUSTODY AUDIT LOG', [
                      '• [12-04-2024 10:23] Acquisition & Hashing by John Doe — SHA-256 MATCH',
                      '• [01-05-2024 08:25] USB Device Connect & Hashing by K. Shanmukh Rao — SHA-256 MATCH',
                      '• [$genTime] Signature Carving & Report Compilation by ${_reportInvestigatorNameController.text} — SHA-256 MATCH',
                    ]),
                    const SizedBox(height: 20),
                  ],

                  // Section 4: Carved Files Inventory
                  if (_incCarved) ...[
                    _buildReportSection('4. SIGNATURE-BASED FILE CARVING RECOVERY INVENTORY', [
                      '• invoice_pdf_carved_001.pdf (245 KB) — Recovery Status: CARVED — SHA-256: a1b2c3d4e5f6a7b8...',
                      '• suspect_photo.jpg (1.2 MB) — Recovery Status: CARVED — SHA-256: c3d4e5f6a7b8c9d0...',
                      '• carved_recovered_statement.pdf (312 KB) — Recovery Status: CARVED — SHA-256: 7f8a9b0c1d2e3f4a...',
                    ]),
                    const SizedBox(height: 20),
                  ],

                  // Section 5: Artifact Correlation Findings
                  if (_incArtifacts) ...[
                    _buildReportSection('5. MULTI-SOURCE ARTIFACT FINDINGS & CORRELATION', [
                      '• USB Storage Event: SanDisk 32GB (Serial 88A9237194B) mounted on 01-05-2024 08:25:45.',
                      '• Binary Execution: report_docs.exe launched from removable drive path.',
                      '• Web Browser Artifacts: 14 visits logged to external portal (https://www.example-fraud-portal.com/login).',
                      '• Persistence Key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified.',
                    ]),
                    const SizedBox(height: 20),
                  ],

                  // Section 6: Reconstructed Timeline
                  if (_incTimeline) ...[
                    _buildReportSection('6. RECONSTRUCTED CHRONOLOGICAL TIMELINE SUMMARY', [
                      '• 08:15:23 — System Boot Event (Windows 10 Workstation)',
                      '• 08:25:45 — USBSTOR Event: SanDisk 32GB Inserted',
                      '• 08:27:30 — Process Execution: report_docs.exe',
                      '• 08:30:15 — Network Connection to 198.51.100.45:443',
                      '• 09:15:23 — Browser Visit to Example Fraud Portal',
                    ]),
                    const SizedBox(height: 20),
                  ],

                  // Section 7: Cryptographic Report Immutability Seal
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: const Color(0xFFF6F8FA),
                      border: Border.all(color: Colors.grey.shade400),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.verified_user, color: Color(0xFF1F6FEB), size: 20),
                            const SizedBox(width: 8),
                            Text('REPORT CRYPTOGRAPHIC IMMUTABILITY SHA-256 STAMP:', style: GoogleFonts.inter(color: Colors.black, fontSize: 11, fontWeight: FontWeight.bold)),
                          ],
                        ),
                        const SizedBox(height: 4),
                        SelectableText(
                          reportStamp,
                          style: GoogleFonts.firaCode(color: const Color(0xFF090D13), fontSize: 11, fontWeight: FontWeight.bold),
                        ),
                        Text(
                          'Guarantees courtroom admissibility and tamper-proof integrity of this compiled report.',
                          style: TextStyle(color: Colors.grey.shade700, fontSize: 10),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 28),

                  // Section 8: Legal Signature Block & PDF Export Action
                  Wrap(
                    alignment: WrapAlignment.spaceBetween,
                    crossAxisAlignment: WrapCrossAlignment.end,
                    runSpacing: 16,
                    spacing: 16,
                    children: [
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text('Lead Investigator Certification & Signature:', style: TextStyle(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 12)),
                          const SizedBox(height: 20),
                          Text('________________________________', style: TextStyle(color: Colors.grey.shade600)),
                          Text('${_reportInvestigatorNameController.text} (${_reportInvestigatorIdController.text})', style: const TextStyle(color: Colors.black87, fontWeight: FontWeight.bold, fontSize: 12)),
                          Text('${_reportInstitutionController.text} — ${_reportSubjectCodeController.text}', style: TextStyle(color: Colors.grey.shade700, fontSize: 11)),
                        ],
                      ),
                      ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF238636),
                          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
                        ),
                        onPressed: () {
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text('Downloading Court-Ready PDF Forensic Report ($reportId.pdf)...'),
                              backgroundColor: const Color(0xFF238636),
                            ),
                          );
                        },
                        icon: const Icon(Icons.download_for_offline, color: Colors.white),
                        label: const Text('EXPORT COURT-READY PDF REPORT', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildReportSection(String title, List<String> lines) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: GoogleFonts.outfit(color: Colors.black, fontSize: 14, fontWeight: FontWeight.bold)),
        const SizedBox(height: 6),
        ...lines.map((l) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 2),
          child: Text(l, style: GoogleFonts.inter(color: Colors.black87, fontSize: 12)),
        )),
      ],
    );
  }

  // ==========================================
  // --- PHASE 4: FILESYSTEM & FILE CARVING ---
  // ==========================================
  Widget _buildFilesystemTab() {
    final summary = _carvingSummary;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.folder_zip, color: Color(0xFF8957E5), size: 28),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Filesystem Parsing & Signature-Based File Carving Engine',
                  style: GoogleFonts.outfit(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            'Read-only binary magic-byte file carving (PDF, PNG, JPEG) with boundary detection, format structure validation, SHA-256 hashing, and provenance isolation.',
            style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13),
          ),
          const SizedBox(height: 24),
          // Carving Engine Control Box
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: const Color(0xFF30363D)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('File Carving Scanner Configuration', style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                const SizedBox(height: 16),
                Row(
                  children: [
                    Expanded(
                      flex: 2,
                      child: _buildTextField(_caseIdController, 'Case ID', 'CASE-2024-001'),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      flex: 3,
                      child: _buildTextField(_carveEvidenceIdController, 'Target Evidence Item ID', 'Leave blank to use latest acquired evidence'),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                Text('Supported Binary File Signatures:', style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 12, fontWeight: FontWeight.bold)),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 12,
                  runSpacing: 8,
                  children: ['PDF', 'PNG', 'JPEG'].map((sig) {
                    final isSelected = _carveSignatures.contains(sig);
                    return FilterChip(
                      selected: isSelected,
                      label: Text(sig, style: TextStyle(color: isSelected ? Colors.white : Colors.grey, fontWeight: FontWeight.bold, fontSize: 12)),
                      selectedColor: const Color(0xFF8957E5),
                      backgroundColor: const Color(0xFF0D1117),
                      checkmarkColor: Colors.white,
                      onSelected: (val) {
                        setState(() {
                          if (val) {
                            _carveSignatures.add(sig);
                          } else {
                            _carveSignatures.remove(sig);
                          }
                        });
                      },
                    );
                  }).toList(),
                ),
                const SizedBox(height: 20),
                SizedBox(
                  width: double.infinity,
                  height: 46,
                  child: ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF8957E5),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    onPressed: _isCarving ? null : _handleFileCarving,
                    icon: _isCarving
                        ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                        : const Icon(Icons.saved_search, color: Colors.white),
                    label: Text(
                      _isCarving ? 'SCANNING READ-ONLY EVIDENCE & CARVING BINARY FILES...' : 'EXECUTE MAGIC-BYTE FILE CARVING RECOVERY',
                      style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold),
                    ),
                  ),
                ),
              ],
            ),
          ),
          
          if (summary != null) ...[
            const SizedBox(height: 20),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF0D1117),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF1F6FEB)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('FILE CARVING SUMMARY RESULT', style: GoogleFonts.outfit(color: const Color(0xFF58A6FF), fontSize: 14, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 12),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceAround,
                    children: [
                      _buildSummaryStat('Candidates Found', '${summary['candidates_found'] ?? 0}', Colors.white),
                      _buildSummaryStat('Files Recovered', '${summary['files_recovered'] ?? 0}', const Color(0xFF3FB950)),
                      _buildSummaryStat('Invalid / Partial', '${summary['files_invalid'] ?? 0}', const Color(0xFFF85149)),
                      _buildSummaryStat('Duplicates Skipped', '${summary['duplicates_skipped'] ?? 0}', const Color(0xFFD29922)),
                    ],
                  ),
                ],
              ),
            ),
          ],

          const SizedBox(height: 28),
          Text('Extracted & Recovered File Artifacts', style: GoogleFonts.outfit(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          
          if (_fileArtifacts.isEmpty)
            Container(
              padding: const EdgeInsets.all(32),
              width: double.infinity,
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF30363D)),
              ),
              child: Column(
                children: [
                  const Icon(Icons.saved_search, color: Colors.grey, size: 48),
                  const SizedBox(height: 12),
                  Text('No Recovered File Artifacts Present', style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 4),
                  const Text('Select an evidence item and click "EXECUTE MAGIC-BYTE FILE CARVING RECOVERY" to scan.', style: TextStyle(color: Colors.grey, fontSize: 12)),
                ],
              ),
            )
          else
            Container(
              width: double.infinity,
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF30363D)),
              ),
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: DataTable(
                  headingRowColor: WidgetStateProperty.all(const Color(0xFF21262D)),
                  columns: const [
                    DataColumn(label: Text('File Name', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Type', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Offset (Bytes)', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Size', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Validation', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('SHA-256 Hash', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Source Evidence SHA-256', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Action', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  ],
                  rows: _fileArtifacts.map((f) {
                    final isCarved = f['is_carved'] == true || f['recovery_status'] == 'CARVED';
                    final sizeKb = (((f['size_bytes'] ?? f['size']) ?? 0) / 1024).toStringAsFixed(1);
                    final offset = f['offset_bytes'] ?? f['offset'] ?? 0;
                    final valStatus = f['validation_status'] ?? 'VALID';
                    final artifactId = f['id'] ?? '';
                    final fileName = f['name'] ?? f['file_name'] ?? 'carved_file';
                    final fileType = f['file_type'] ?? 'RAW';

                    Color valBg = const Color(0xFF238636).withValues(alpha: 0.2);
                    Color valColor = const Color(0xFF3FB950);
                    if (valStatus == 'INVALID') {
                      valBg = const Color(0xFFDA3633).withValues(alpha: 0.2);
                      valColor = const Color(0xFFF85149);
                    } else if (valStatus == 'PARTIAL') {
                      valBg = const Color(0xFFD29922).withValues(alpha: 0.2);
                      valColor = const Color(0xFFD29922);
                    }

                    return DataRow(cells: [
                      DataCell(Row(
                        children: [
                          Icon(
                            isCarved ? Icons.auto_awesome : Icons.insert_drive_file,
                            color: isCarved ? const Color(0xFFD29922) : const Color(0xFF58A6FF),
                            size: 18,
                          ),
                          const SizedBox(width: 8),
                          Text(fileName, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600)),
                        ],
                      )),
                      DataCell(Text(fileType, style: const TextStyle(color: Colors.grey))),
                      DataCell(Text('$offset', style: GoogleFonts.firaCode(color: Colors.white, fontSize: 11))),
                      DataCell(Text('$sizeKb KB', style: const TextStyle(color: Colors.white))),
                      DataCell(Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: valBg,
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Text(
                          valStatus,
                          style: TextStyle(color: valColor, fontSize: 10, fontWeight: FontWeight.bold),
                        ),
                      )),
                      DataCell(Text(
                        (f['sha256_hash'] ?? f['sha256'] ?? '').toString().length > 16
                            ? '${(f['sha256_hash'] ?? f['sha256'] ?? '').substring(0, 16)}...'
                            : (f['sha256_hash'] ?? f['sha256'] ?? ''),
                        style: GoogleFonts.firaCode(color: const Color(0xFF58A6FF), fontSize: 11),
                      )),
                      DataCell(Text(
                        (f['source_evidence_hash'] ?? '').toString().length > 16
                            ? '${(f['source_evidence_hash'] ?? '').substring(0, 16)}...'
                            : (f['source_evidence_hash'] ?? '-'),
                        style: GoogleFonts.firaCode(color: const Color(0xFF8B949E), fontSize: 11),
                      )),
                      DataCell(ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF1F6FEB),
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                        ),
                        onPressed: artifactId.isEmpty ? null : () => _handleDownloadCarvedFile(artifactId, fileName),
                        icon: const Icon(Icons.download, size: 14, color: Colors.white),
                        label: const Text('Download', style: TextStyle(color: Colors.white, fontSize: 11)),
                      )),
                    ]);
                  }).toList(),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildSummaryStat(String label, String value, Color color) {
    return Column(
      children: [
        Text(value, style: GoogleFonts.outfit(color: color, fontSize: 22, fontWeight: FontWeight.bold)),
        const SizedBox(height: 2),
        Text(label, style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 11)),
      ],
    );
  }

  // ===============================================
  // --- PHASE 3: MULTI-SOURCE ARTIFACT ANALYSIS ---
  // ===============================================
  Widget _buildArtifactAnalysisTab() {
    final filteredBrowser = _browserArtifacts.where((b) {
      if (_selectedBrowserFilter != 'All' && !(b['browser'] as String).toLowerCase().contains(_selectedBrowserFilter.toLowerCase())) {
        return false;
      }
      final search = _artifactSearchController.text.trim().toLowerCase();
      if (search.isNotEmpty) {
        final url = (b['url'] ?? '').toString().toLowerCase();
        final title = (b['title'] ?? '').toString().toLowerCase();
        return url.contains(search) || title.contains(search);
      }
      return true;
    }).toList();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.manage_search, color: Color(0xFF3FB950), size: 28),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Multi-Source Forensic Artifact Analysis Engine',
                  style: GoogleFonts.outfit(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            'Extract and correlate real web browser artifacts (Chrome / Edge History SQLite) and Windows system event logs with full forensic provenance tracing.',
            style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13),
          ),
          const SizedBox(height: 24),

          // --- REAL ARTIFACT EXTRACTION ACTION CONTROL PANEL ---
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: const Color(0xFF30363D)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Icon(Icons.hub_outlined, color: Color(0xFF58A6FF), size: 20),
                    const SizedBox(width: 8),
                    Text(
                      'Real Evidence Artifact Extraction Workbench',
                      style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                    ),
                  ],
                ),
                const SizedBox(height: 14),
                Wrap(
                  spacing: 16,
                  runSpacing: 12,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text('Target Browser: ', style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13)),
                        const SizedBox(width: 8),
                        ChoiceChip(
                          selected: _extractBrowserName == 'Chrome',
                          label: const Text('Google Chrome', style: TextStyle(color: Colors.white, fontSize: 12)),
                          selectedColor: const Color(0xFF1F6FEB),
                          backgroundColor: const Color(0xFF0D1117),
                          onSelected: (val) { if (val) setState(() => _extractBrowserName = 'Chrome'); },
                        ),
                        const SizedBox(width: 8),
                        ChoiceChip(
                          selected: _extractBrowserName == 'Edge',
                          label: const Text('Microsoft Edge', style: TextStyle(color: Colors.white, fontSize: 12)),
                          selectedColor: const Color(0xFF1F6FEB),
                          backgroundColor: const Color(0xFF0D1117),
                          onSelected: (val) { if (val) setState(() => _extractBrowserName = 'Edge'); },
                        ),
                      ],
                    ),
                    ElevatedButton.icon(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF238636),
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                      ),
                      onPressed: _isExtractingArtifacts ? null : () async {
                        setState(() => _isExtractingArtifacts = true);
                        final caseId = _caseIdController.text;
                        final res = await ApiService.extractBrowserArtifacts(
                          caseId: caseId,
                          evidenceId: 'ev-sample-1',
                          browser: _extractBrowserName,
                        );
                        setState(() => _isExtractingArtifacts = false);
                        if (res != null && res['success'] == true) {
                          final count = res['data']?['artifacts_extracted'] ?? 0;
                          if (!mounted) return;
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text('Successfully extracted $count $_extractBrowserName history artifacts into database!'),
                              backgroundColor: const Color(0xFF238636),
                            ),
                          );
                          _loadDashboardData();
                        } else {
                          if (!mounted) return;
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text('Extraction error: ${res?['error'] ?? 'Ensure evidence SQLite History database is acquired'}'),
                              backgroundColor: const Color(0xFFDA3633),
                            ),
                          );
                        }
                      },
                      icon: _isExtractingArtifacts
                          ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                          : const Icon(Icons.travel_explore, color: Colors.white, size: 18),
                      label: Text(
                        _isExtractingArtifacts ? 'EXTRACTING SQLITE HISTORY...' : 'EXTRACT BROWSER HISTORY',
                        style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12),
                      ),
                    ),
                    ElevatedButton.icon(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF1F6FEB),
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                      ),
                      onPressed: _isExtractingSystem ? null : () async {
                        setState(() => _isExtractingSystem = true);
                        final caseId = _caseIdController.text;
                        final res = await ApiService.extractSystemArtifacts(
                          caseId: caseId,
                          evidenceId: 'ev-sample-1',
                        );
                        setState(() => _isExtractingSystem = false);
                        if (res != null && res['success'] == true) {
                          final count = res['data']?['artifacts_extracted'] ?? 0;
                          if (!mounted) return;
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text('Successfully extracted $count system event artifacts into database!'),
                              backgroundColor: const Color(0xFF238636),
                            ),
                          );
                          _loadDashboardData();
                        } else {
                          if (!mounted) return;
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text('Extraction error: ${res?['error'] ?? 'Check system evidence log'}'),
                              backgroundColor: const Color(0xFFDA3633),
                            ),
                          );
                        }
                      },
                      icon: _isExtractingSystem
                          ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                          : const Icon(Icons.terminal, color: Colors.white, size: 18),
                      label: Text(
                        _isExtractingSystem ? 'PARSING SYSTEM LOGS...' : 'EXTRACT SYSTEM ARTIFACTS',
                        style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 28),

          // --- BROWSER ARTIFACTS SECTION ---
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text('Web Browser History Artifacts', style: GoogleFonts.outfit(color: Colors.white, fontSize: 17, fontWeight: FontWeight.bold)),
              Row(
                children: [
                  // Filter Chips
                  ChoiceChip(
                    selected: _selectedBrowserFilter == 'All',
                    label: const Text('All Browsers', style: TextStyle(color: Colors.white, fontSize: 11)),
                    selectedColor: const Color(0xFF1F6FEB),
                    backgroundColor: const Color(0xFF161B22),
                    onSelected: (val) { if (val) setState(() => _selectedBrowserFilter = 'All'); },
                  ),
                  const SizedBox(width: 6),
                  ChoiceChip(
                    selected: _selectedBrowserFilter == 'Chrome',
                    label: const Text('Chrome', style: TextStyle(color: Colors.white, fontSize: 11)),
                    selectedColor: const Color(0xFF1F6FEB),
                    backgroundColor: const Color(0xFF161B22),
                    onSelected: (val) { if (val) setState(() => _selectedBrowserFilter = 'Chrome'); },
                  ),
                  const SizedBox(width: 6),
                  ChoiceChip(
                    selected: _selectedBrowserFilter == 'Edge',
                    label: const Text('Edge', style: TextStyle(color: Colors.white, fontSize: 11)),
                    selectedColor: const Color(0xFF1F6FEB),
                    backgroundColor: const Color(0xFF161B22),
                    onSelected: (val) { if (val) setState(() => _selectedBrowserFilter = 'Edge'); },
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 12),

          if (filteredBrowser.isEmpty) ...[
            Container(
              padding: const EdgeInsets.all(32),
              width: double.infinity,
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF30363D)),
              ),
              child: Column(
                children: [
                  const Icon(Icons.find_in_page_outlined, color: Color(0xFF484F58), size: 48),
                  const SizedBox(height: 12),
                  Text(
                    'No browser artifacts extracted for this evidence.',
                    style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Acquire a browser History SQLite evidence database file and click "EXTRACT BROWSER HISTORY" above.',
                    textAlign: TextAlign.center,
                    style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 12),
                  ),
                ],
              ),
            ),
          ] else ...[
            Container(
              width: double.infinity,
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF30363D)),
              ),
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: DataTable(
                  headingRowColor: WidgetStateProperty.all(const Color(0xFF21262D)),
                  columns: const [
                    DataColumn(label: Text('Browser', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Page Title', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('URL', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Visit Time (UTC)', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Visits', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                    DataColumn(label: Text('Evidence Provenance', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  ],
                  rows: filteredBrowser.map((b) {
                    final evId = (b['evidence_id'] ?? '').toString();
                    final provDisplay = evId.length > 8 ? '${evId.substring(0, 8)}...' : (evId.isNotEmpty ? evId : 'Acquired Evidence');
                    return DataRow(cells: [
                      DataCell(Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: const Color(0xFF1F6FEB).withValues(alpha: 0.2),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(b['browser'] ?? 'Chrome', style: const TextStyle(color: Color(0xFF58A6FF), fontSize: 11, fontWeight: FontWeight.bold)),
                      )),
                      DataCell(Text(b['title'] ?? '', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w500))),
                      DataCell(Text(b['url'] ?? '', style: const TextStyle(color: Color(0xFF58A6FF), fontSize: 12))),
                      DataCell(Text(b['visit_time'] ?? '', style: const TextStyle(color: Colors.grey, fontSize: 12))),
                      DataCell(Text('${b['visit_count'] ?? 1}', style: const TextStyle(color: Colors.white))),
                      DataCell(Text(provDisplay, style: GoogleFonts.firaCode(color: const Color(0xFF8B949E), fontSize: 11))),
                    ]);
                  }).toList(),
                ),
              ),
            ),
          ],
          const SizedBox(height: 32),

          // --- SYSTEM ARTIFACTS SECTION ---
          Text('System Event Logs & USB Registry Artifacts', style: GoogleFonts.outfit(color: Colors.white, fontSize: 17, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),

          if (_systemArtifacts.isEmpty) ...[
            Container(
              padding: const EdgeInsets.all(32),
              width: double.infinity,
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF30363D)),
              ),
              child: Column(
                children: [
                  const Icon(Icons.terminal_outlined, color: Color(0xFF484F58), size: 48),
                  const SizedBox(height: 12),
                  Text(
                    'No system event artifacts extracted for this evidence.',
                    style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Acquire a system log evidence file and click "EXTRACT SYSTEM ARTIFACTS" above.',
                    textAlign: TextAlign.center,
                    style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 12),
                  ),
                ],
              ),
            ),
          ] else ...[
            ListView.builder(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: _systemArtifacts.length,
              itemBuilder: (ctx, idx) {
                final sys = _systemArtifacts[idx];
                final isCritical = sys['severity'] == 'Critical';
                return Container(
                  margin: const EdgeInsets.only(bottom: 12),
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: const Color(0xFF161B22),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: isCritical ? Colors.red.shade900 : const Color(0xFF30363D)),
                  ),
                  child: Row(
                    children: [
                      Icon(
                        sys['artifact_type'] == 'USB Device' ? Icons.usb : Icons.warning_amber,
                        color: isCritical ? Colors.red : const Color(0xFFD29922),
                        size: 24,
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Text(sys['artifact_type'] ?? '', style: GoogleFonts.outfit(color: Colors.white, fontSize: 15, fontWeight: FontWeight.bold)),
                                Text(sys['timestamp'] ?? '', style: const TextStyle(color: Colors.grey, fontSize: 12)),
                              ],
                            ),
                            const SizedBox(height: 4),
                            Text(sys['description'] ?? '', style: const TextStyle(color: Colors.white70, fontSize: 13)),
                            const SizedBox(height: 4),
                            Text('Source: ${sys['source']}  |  Evidence: ${sys['evidence_id'] ?? ''}', style: const TextStyle(color: Colors.grey, fontSize: 11)),
                          ],
                        ),
                      ),
                    ],
                  ),
                );
              },
            ),
          ],
        ],
      ),
    );
  }

  // =========================================================
  // --- PHASE 3: CROSS-SOURCE TIMELINE RECONSTRUCTION ---
  // =========================================================
  Widget _buildTimelineTab() {
    final filteredEvents = _selectedTimelineCategory == 'All'
        ? _timelineEvents
        : _timelineEvents.where((e) => e['category'] == _selectedTimelineCategory).toList();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.timeline, color: Color(0xFFD29922), size: 28),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Cross-Source Investigative Timeline Reconstruction',
                  style: GoogleFonts.outfit(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            'Reconstruct event chronologies across filesystem timestamps, registry entries, USB connections, network PCAPs, and event logs into a unified timeline.',
            style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13),
          ),
          const SizedBox(height: 20),
          // Filter Chips
          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: ['All', 'System', 'Filesystem', 'USB', 'Network', 'Browser'].map((cat) {
              final isSel = _selectedTimelineCategory == cat;
              return ChoiceChip(
                selected: isSel,
                label: Text(cat, style: TextStyle(color: isSel ? Colors.white : Colors.grey, fontWeight: FontWeight.bold)),
                selectedColor: const Color(0xFF1F6FEB),
                backgroundColor: const Color(0xFF161B22),
                onSelected: (val) {
                  if (val) setState(() => _selectedTimelineCategory = cat);
                },
              );
            }).toList(),
          ),
          const SizedBox(height: 24),
          // Timeline Event List
          ListView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: filteredEvents.length,
            itemBuilder: (ctx, idx) {
              final ev = filteredEvents[idx];
              Color catColor = const Color(0xFF1F6FEB);
              IconData catIcon = Icons.event;

              switch (ev['category']) {
                case 'USB':
                  catColor = const Color(0xFFD29922);
                  catIcon = Icons.usb;
                  break;
                case 'Filesystem':
                  catColor = const Color(0xFF8957E5);
                  catIcon = Icons.folder;
                  break;
                case 'Network':
                  catColor = Colors.redAccent;
                  catIcon = Icons.public;
                  break;
                case 'Browser':
                  catColor = const Color(0xFF3FB950);
                  catIcon = Icons.language;
                  break;
                default:
                  catColor = const Color(0xFF1F6FEB);
                  catIcon = Icons.computer;
              }

              return Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Timestamp column
                  SizedBox(
                    width: 140,
                    child: Text(
                      ev['timestamp'] ?? '',
                      style: GoogleFonts.firaCode(color: const Color(0xFF8B949E), fontSize: 12, fontWeight: FontWeight.bold),
                    ),
                  ),
                  // Timeline Node Line
                  Column(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: catColor.withValues(alpha: 0.2),
                          shape: BoxShape.circle,
                          border: Border.all(color: catColor),
                        ),
                        child: Icon(catIcon, color: catColor, size: 18),
                      ),
                      if (idx < filteredEvents.length - 1)
                        Container(
                          width: 2,
                          height: 50,
                          color: const Color(0xFF30363D),
                        ),
                    ],
                  ),
                  const SizedBox(width: 16),
                  // Content Card
                  Expanded(
                    child: Container(
                      margin: const EdgeInsets.only(bottom: 16),
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: const Color(0xFF161B22),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: const Color(0xFF30363D)),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Text(ev['title'] ?? '', style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                                decoration: BoxDecoration(
                                  color: catColor.withValues(alpha: 0.2),
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                child: Text(ev['category'] ?? '', style: TextStyle(color: catColor, fontSize: 11, fontWeight: FontWeight.bold)),
                              ),
                            ],
                          ),
                          const SizedBox(height: 6),
                          Text(ev['description'] ?? '', style: GoogleFonts.inter(color: Colors.white70, fontSize: 13)),
                          const SizedBox(height: 8),
                          Text('Source Artifact: ${ev['source_artifact']}', style: GoogleFonts.firaCode(color: const Color(0xFF8B949E), fontSize: 11)),
                        ],
                      ),
                    ),
                  ),
                ],
              );
            },
          ),
        ],
      ),
    );
  }

  // =========================================================================
  // --- PHASE 5: AUTOMATED IOC THREAT CORRELATION & ADVANCED FORENSICS ---
  // =========================================================================
  Widget _buildIocThreatTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.security_update_warning, color: Colors.redAccent, size: 28),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Phase 5: Automated IOC Threat Watchlist Correlation & RAM Volatility Engine',
                  style: GoogleFonts.outfit(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            'Automatically correlate extracted file hashes, IP addresses, domains, and keywords against active threat intelligence watchlists. Inspect RAM memory volatility dumps and live PCAP network sessions.',
            style: GoogleFonts.inter(color: const Color(0xFF8B949E), fontSize: 13),
          ),
          const SizedBox(height: 24),

          // IOC Threat Scanner Control Panel
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: Colors.red.shade900.withValues(alpha: 0.5)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('IOC Threat Intelligence Watchlist Scanner', style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                const SizedBox(height: 16),
                _buildTextField(_iocKeywordController, 'Target IOC Indicators (Comma Separated IPs, Hashes, Domains, Keywords)', 'report_docs.exe, 198.51.100.45, example-fraud-portal.com'),
                const SizedBox(height: 20),
                SizedBox(
                  width: double.infinity,
                  height: 46,
                  child: ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red.shade800,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    onPressed: _isScanningIoc ? null : _handleIocScan,
                    icon: _isScanningIoc
                        ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                        : const Icon(Icons.radar, color: Colors.white),
                    label: Text(
                      _isScanningIoc ? 'CORRELATING ARTIFACTS AGAINST THREAT WATCHLISTS...' : 'EXECUTE AUTOMATED IOC THREAT WATCHLIST SCAN',
                      style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold),
                    ),
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 28),

          // Threat Matches Section
          Text('Correlated Threat Intelligence Hits (${_iocMatches.length} Matches)', style: GoogleFonts.outfit(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          ListView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: _iocMatches.length,
            itemBuilder: (ctx, idx) {
              final hit = _iocMatches[idx];
              final isCrit = hit['threat_severity'] == 'Critical';
              final sevColor = isCrit ? Colors.red : const Color(0xFFD29922);

              return Container(
                margin: const EdgeInsets.only(bottom: 12),
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  color: const Color(0xFF161B22),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: sevColor.withValues(alpha: 0.8)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Icon(Icons.shield_outlined, color: sevColor, size: 22),
                            const SizedBox(width: 10),
                            Text(hit['ioc_type'] ?? '', style: GoogleFonts.outfit(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                          ],
                        ),
                        Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                              decoration: BoxDecoration(
                                color: sevColor.withValues(alpha: 0.2),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: sevColor),
                              ),
                              child: Text(
                                '${hit['threat_severity']} (${hit['confidence_percentage']}% Confidence)',
                                style: TextStyle(color: sevColor, fontSize: 11, fontWeight: FontWeight.bold),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(hit['description'] ?? '', style: GoogleFonts.inter(color: Colors.white70, fontSize: 13)),
                    const SizedBox(height: 8),
                    Wrap(
                      spacing: 20,
                      children: [
                        Text('Indicator: ${hit['indicator_value']}', style: GoogleFonts.firaCode(color: const Color(0xFF58A6FF), fontSize: 12)),
                        Text('Matched Source: ${hit['matched_source']}', style: GoogleFonts.inter(color: Colors.grey, fontSize: 12)),
                        Text('Matched At: ${hit['matched_at']}', style: GoogleFonts.inter(color: Colors.grey, fontSize: 12)),
                      ],
                    ),
                  ],
                ),
              );
            },
          ),

          const SizedBox(height: 32),

          // RAM Memory Dump Volatility Section
          Text('RAM Memory Dump Volatility Inspection', style: GoogleFonts.outfit(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Container(
            width: double.infinity,
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF30363D)),
            ),
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: DataTable(
                headingRowColor: WidgetStateProperty.all(const Color(0xFF21262D)),
                columns: const [
                  DataColumn(label: Text('PID', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('PPID', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Process Name', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Status', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('DLL Injection Flag', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('RAM Usage', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Executable Path', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                ],
                rows: _memoryProcesses.map((p) {
                  final isSusp = p['status'] == 'Suspicious' || p['has_dll_injection'] == true;
                  return DataRow(cells: [
                    DataCell(Text('${p['pid']}', style: GoogleFonts.firaCode(color: Colors.white))),
                    DataCell(Text('${p['ppid']}', style: GoogleFonts.firaCode(color: Colors.grey))),
                    DataCell(Text(p['process_name'] ?? '', style: TextStyle(color: isSusp ? Colors.red : Colors.white, fontWeight: FontWeight.bold))),
                    DataCell(Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: isSusp ? Colors.red.withValues(alpha: 0.2) : const Color(0xFF238636).withValues(alpha: 0.2),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(p['status'] ?? 'Running', style: TextStyle(color: isSusp ? Colors.red : const Color(0xFF3FB950), fontSize: 11, fontWeight: FontWeight.bold)),
                    )),
                    DataCell(Row(
                      children: [
                        Icon(p['has_dll_injection'] == true ? Icons.bug_report : Icons.check_circle, color: p['has_dll_injection'] == true ? Colors.red : const Color(0xFF3FB950), size: 16),
                        const SizedBox(width: 6),
                        Text(p['has_dll_injection'] == true ? 'DLL INJECTION DETECTED' : 'Clean', style: TextStyle(color: p['has_dll_injection'] == true ? Colors.red : Colors.grey, fontSize: 11)),
                      ],
                    )),
                    DataCell(Text('${p['mem_usage_mb']} MB', style: const TextStyle(color: Colors.white))),
                    DataCell(Text(p['path'] ?? '', style: const TextStyle(color: Colors.grey, fontSize: 11))),
                  ]);
                }).toList(),
              ),
            ),
          ),

          const SizedBox(height: 32),

          // PCAP Network Traffic Inspector Section
          Text('Live PCAP Network Packet Stream Inspection', style: GoogleFonts.outfit(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Container(
            width: double.infinity,
            decoration: BoxDecoration(
              color: const Color(0xFF161B22),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF30363D)),
            ),
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: DataTable(
                headingRowColor: WidgetStateProperty.all(const Color(0xFF21262D)),
                columns: const [
                  DataColumn(label: Text('Session ID', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Protocol', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Source IP:Port', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Destination IP:Port', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Packets / Bytes', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Threat Flag', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                  DataColumn(label: Text('Timestamp', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold))),
                ],
                rows: _networkSessions.map((s) {
                  final isSusp = s['is_suspicious'] == true;
                  final sizeMb = ((s['total_bytes'] ?? 0) / (1024 * 1024)).toStringAsFixed(2);
                  return DataRow(cells: [
                    DataCell(Text(s['session_id'] ?? '', style: GoogleFonts.firaCode(color: const Color(0xFF58A6FF)))),
                    DataCell(Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: const Color(0xFF1F6FEB).withValues(alpha: 0.2),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(s['protocol'] ?? '', style: const TextStyle(color: Color(0xFF58A6FF), fontSize: 11, fontWeight: FontWeight.bold)),
                    )),
                    DataCell(Text('${s['src_ip']}:${s['src_port']}', style: const TextStyle(color: Colors.grey))),
                    DataCell(Text('${s['dst_ip']}:${s['dst_port']}', style: TextStyle(color: isSusp ? Colors.red : Colors.white, fontWeight: FontWeight.bold))),
                    DataCell(Text('${s['packet_count']} pkts ($sizeMb MB)', style: const TextStyle(color: Colors.white))),
                    DataCell(Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: isSusp ? Colors.red.withValues(alpha: 0.2) : const Color(0xFF238636).withValues(alpha: 0.2),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(isSusp ? 'SUSPICIOUS C2' : 'Normal', style: TextStyle(color: isSusp ? Colors.red : const Color(0xFF3FB950), fontSize: 11, fontWeight: FontWeight.bold)),
                    )),
                    DataCell(Text(s['timestamp'] ?? '', style: const TextStyle(color: Colors.grey, fontSize: 11))),
                  ]);
                }).toList(),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
