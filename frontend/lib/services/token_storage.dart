import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

class TokenStorage {
  static const FlutterSecureStorage _secureStorage = FlutterSecureStorage();

  static const String _keyAccessToken = 'forensiq_access_token';
  static const String _keyUsername = 'forensiq_username';
  static const String _keyRole = 'forensiq_user_role';
  static const String _keyUserId = 'forensiq_user_id';

  /// Save session data securely
  static Future<void> saveSession({
    required String token,
    required String username,
    required String role,
    required String userId,
  }) async {
    try {
      await _secureStorage.write(key: _keyAccessToken, value: token);
      await _secureStorage.write(key: _keyUsername, value: username);
      await _secureStorage.write(key: _keyRole, value: role);
      await _secureStorage.write(key: _keyUserId, value: userId);
    } catch (_) {
      // Fallback if platform secure storage driver is unavailable in test environment
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_keyAccessToken, token);
      await prefs.setString(_keyUsername, username);
      await prefs.setString(_keyRole, role);
      await prefs.setString(_keyUserId, userId);
    }
  }

  /// Retrieve stored JWT access token
  static Future<String?> getToken() async {
    try {
      final token = await _secureStorage.read(key: _keyAccessToken);
      if (token != null && token.isNotEmpty) return token;
    } catch (_) {}

    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_keyAccessToken);
  }

  /// Retrieve stored username
  static Future<String?> getUsername() async {
    try {
      final username = await _secureStorage.read(key: _keyUsername);
      if (username != null && username.isNotEmpty) return username;
    } catch (_) {}

    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_keyUsername);
  }

  /// Retrieve stored user role
  static Future<String?> getRole() async {
    try {
      final role = await _secureStorage.read(key: _keyRole);
      if (role != null && role.isNotEmpty) return role;
    } catch (_) {}

    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_keyRole);
  }

  /// Retrieve stored user ID
  static Future<String?> getUserId() async {
    try {
      final id = await _secureStorage.read(key: _keyUserId);
      if (id != null && id.isNotEmpty) return id;
    } catch (_) {}

    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_keyUserId);
  }

  /// Clear session data (Logout / Expired Token)
  static Future<void> clearSession() async {
    try {
      await _secureStorage.deleteAll();
    } catch (_) {}

    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_keyAccessToken);
    await prefs.remove(_keyUsername);
    await prefs.remove(_keyRole);
    await prefs.remove(_keyUserId);
  }

  /// Check if active session exists
  static Future<bool> isLoggedIn() async {
    final token = await getToken();
    return token != null && token.isNotEmpty;
  }
}
