import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'screens/dashboard_screen.dart';
import 'screens/login_screen.dart';
import 'services/api_service.dart';
import 'services/token_storage.dart';

final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  // Register 401 Unauthorized callback for global session redirection
  ApiService.onUnauthorized = () {
    navigatorKey.currentState?.pushAndRemoveUntil(
      MaterialPageRoute(
        builder: (_) => const LoginScreen(
          initialErrorMessage: 'Session expired. Please log in again.',
        ),
      ),
      (route) => false,
    );
  };

  runApp(const ForensiQApp());
}

class ForensiQApp extends StatelessWidget {
  const ForensiQApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ForensiQ — Digital Forensic Investigation Toolkit',
      navigatorKey: navigatorKey,
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0D1117),
        primaryColor: const Color(0xFF007ACC),
        cardColor: const Color(0xFF161B22),
        canvasColor: const Color(0xFF090D13),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF1F6FEB),
          secondary: Color(0xFF238636),
          surface: Color(0xFF161B22),
          error: Color(0xFFDA3633),
        ),
        textTheme: GoogleFonts.interTextTheme(
          ThemeData.dark().textTheme,
        ),
        useMaterial3: true,
      ),
      home: FutureBuilder<bool>(
        future: TokenStorage.isLoggedIn(),
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Scaffold(
              backgroundColor: Color(0xFF0D1117),
              body: Center(
                child: CircularProgressIndicator(color: Color(0xFF58A6FF)),
              ),
            );
          }
          if (snapshot.data == true) {
            return const DashboardScreen();
          }
          return const LoginScreen();
        },
      ),
    );
  }
}
