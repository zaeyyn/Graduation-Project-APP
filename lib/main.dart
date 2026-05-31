import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'widgets/app_locale.dart';
import 'utils/app_theme.dart';
import 'screens/onboarding_screen.dart';
import 'screens/home_screen.dart';
import 'screens/history_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/stats_screen.dart';
import 'screens/scan_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final prefs = await SharedPreferences.getInstance();
  final onboardingDone = prefs.getBool('onboarding_done') ?? false;

  runApp(
    ChangeNotifierProvider(
      create: (_) => AppLocale(),
      child: LinkGuardApp(
        initialRoute: onboardingDone ? '/home' : '/onboarding',
      ),
    ),
  );
}

class LinkGuardApp extends StatelessWidget {
  final String initialRoute;
  const LinkGuardApp({super.key, required this.initialRoute});

  @override
  Widget build(BuildContext context) {
    final locale = context.watch<AppLocale>();

    return MaterialApp(
      title: 'LinkGuard',
      debugShowCheckedModeBanner: false,
      themeMode: locale.darkMode ? ThemeMode.dark : ThemeMode.light,
      theme: ThemeData(
        fontFamily: 'Roboto',
        colorScheme: ColorScheme.fromSeed(seedColor: AppColors.primary),
        scaffoldBackgroundColor: AppColors.background,
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        fontFamily: 'Roboto',
        brightness: Brightness.dark,
        colorScheme: ColorScheme.fromSeed(
          seedColor: AppColors.primary,
          brightness: Brightness.dark,
        ),
        scaffoldBackgroundColor: AppColors.darkBg,
        cardColor: AppColors.darkCard,
        useMaterial3: true,
      ),
      initialRoute: initialRoute,
      routes: {
        '/onboarding': (_) =>
            const ResponsiveWrapper(child: OnboardingScreen()),
        '/home': (_) => const ResponsiveWrapper(child: HomeScreen()),
        '/history': (_) => const ResponsiveWrapper(child: HistoryScreen()),
        '/settings': (_) => const ResponsiveWrapper(child: SettingsScreen()),
        '/stats': (_) => const ResponsiveWrapper(child: StatsScreen()),
        '/scan': (_) => const ResponsiveWrapper(child: ScanScreen()),
      },
    );
  }
}

class ResponsiveWrapper extends StatelessWidget {
  final Widget child;
  const ResponsiveWrapper({super.key, required this.child});

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 600) return child;
    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2A),
      body: Center(
        child: SizedBox(
          width: 420,
          child: ClipRRect(
            borderRadius: BorderRadius.circular(32),
            child: child,
          ),
        ),
      ),
    );
  }
}