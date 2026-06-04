import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';
import '../widgets/bottom_nav.dart';
import '../services/history_service.dart';
import '../services/api_service.dart';
import '../services/whitelist_service.dart';
import '../services/vpn_service.dart';
import '../models/link_entry.dart';
import 'danger_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  bool _protectionActive = true;
  int _safeCount = 0;
  int _threatCount = 0;
  bool _isChecking = false;

  @override
  void initState() {
    super.initState();
    _loadStats();

    // ابدأ تسمع على الروابط من الـ VPN
    VpnChannel.listenForLinks((url) {
      checkLink(url);
    });
  }

  Future<void> _loadStats() async {
    final stats = await HistoryService.getStats();
    if (mounted) {
      setState(() {
        _safeCount = stats['safe'] ?? 0;
        _threatCount = stats['threats'] ?? 0;
      });
    }
  }

  Future<void> checkLink(String url) async {
    if (!_protectionActive || _isChecking) return;

    // تحقق من الـ whitelist أولاً
    final isTrusted = await WhitelistService.isDomainTrusted(url);
    if (isTrusted) {
      _showSafeSnackbar(context.read<AppLocale>().lang, trusted: true);
      return;
    }

    setState(() => _isChecking = true);
    final result = await ApiService.checkUrl(url);
    final locale = context.read<AppLocale>();
    final domain = Uri.tryParse(url)?.host ?? url;

    final verdictStr = result.verdict == Verdict.danger
        ? 'DANGER'
        : result.verdict == Verdict.warning
            ? 'WARN'
            : 'SAFE';

    await HistoryService.addEntry(LinkEntry(
      domain: domain,
      verdict: verdictStr,
      time: DateTime.now(),
    ));
    await _loadStats();

    if (!mounted) return;
    setState(() => _isChecking = false);

    if (result.verdict == Verdict.danger) {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => DangerScreen(
            url: url,
            threatScore: result.threatScore,
          ),
        ),
      );
    } else {
      _showSafeSnackbar(locale.lang);
    }
  }

  void _showSafeSnackbar(String lang, {bool trusted = false}) {
    final isDark = context.read<AppLocale>().darkMode;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: trusted ? AppColors.primaryLight : AppColors.safe,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(14)),
        margin: const EdgeInsets.all(16),
        duration: const Duration(seconds: 3),
        content: Row(
          children: [
            Icon(
              trusted ? Icons.verified_outlined : Icons.check_circle,
              color: Colors.white,
              size: 22,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    trusted
                        ? (lang == 'ar'
                            ? 'موقع موثوق ✓'
                            : 'Trusted website ✓')
                        : AppTexts.get('safe_notif', lang),
                    style: const TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                    ),
                  ),
                  Text(
                    trusted
                        ? (lang == 'ar'
                            ? 'هذا الموقع في قائمتك الموثوقة'
                            : 'This site is in your trusted list')
                        : AppTexts.get('safe_notif_body', lang),
                    style: TextStyle(
                      color: Colors.white.withOpacity(0.9),
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final locale = context.watch<AppLocale>();
    final t = (String k) => AppTexts.get(k, locale.lang);
    final isAr = locale.isArabic;
    final isDark = locale.darkMode;

    final bgColor = isDark ? AppColors.darkBg : AppColors.background;
    final cardColor = isDark ? AppColors.darkCard : AppColors.cardBg;
    final textPrimary =
        isDark ? AppColors.darkTextPrimary : AppColors.textPrimary;
    final textSecondary =
        isDark ? AppColors.darkTextSecondary : AppColors.textSecondary;

    return Directionality(
      textDirection: isAr ? TextDirection.rtl : TextDirection.ltr,
      child: Scaffold(
        backgroundColor: bgColor,
        body: Column(
          children: [
            // ── Header ──
            Container(
              color: AppColors.primary,
              padding: EdgeInsets.only(
                top: MediaQuery.of(context).padding.top + 16,
                bottom: 20,
                left: 24,
                right: 24,
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        t('protection_is'),
                        style: TextStyle(
                          color: Colors.white.withOpacity(0.8),
                          fontSize: locale.subtitleSize,
                        ),
                      ),
                      Text(
                        'LinkGuard',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: locale.headingSize,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                  // Language switcher
                  GestureDetector(
                    onTap: () => locale.setLang(isAr ? 'en' : 'ar'),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 14, vertical: 7),
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(
                            color: Colors.white.withOpacity(0.3)),
                      ),
                      child: Text(
                        isAr ? 'EN | AR' : 'AR | EN',
                        style: const TextStyle(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 13,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),

            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Column(
                  children: [
                    // ── Protection Card ──
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(24),
                      decoration: BoxDecoration(
                        color: cardColor,
                        borderRadius: BorderRadius.circular(20),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black
                                .withOpacity(isDark ? 0.3 : 0.06),
                            blurRadius: 12,
                            offset: const Offset(0, 4),
                          ),
                        ],
                      ),
                      child: Column(
                        children: [
                          // Shield icon
                          Container(
                            width: 80,
                            height: 80,
                            decoration: BoxDecoration(
                              color: _protectionActive
                                  ? AppColors.accent.withOpacity(0.1)
                                  : Colors.grey.withOpacity(0.1),
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: _protectionActive
                                    ? AppColors.accent
                                    : Colors.grey,
                                width: 2.5,
                              ),
                            ),
                            child: Icon(
                              Icons.security,
                              size: 42,
                              color: _protectionActive
                                  ? AppColors.primary
                                  : Colors.grey,
                            ),
                          ),
                          const SizedBox(height: 16),
                          Text(
                            t('you_are_protected'),
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: locale.titleSize,
                              color: textPrimary,
                            ),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            t('all_links_checked'),
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: textSecondary,
                              fontSize: locale.subtitleSize,
                            ),
                          ),
                          const SizedBox(height: 20),

                          // Toggle row
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 16, vertical: 12),
                            decoration: BoxDecoration(
                              color: isDark
                                  ? AppColors.darkBg
                                  : AppColors.background,
                              borderRadius: BorderRadius.circular(14),
                            ),
                            child: Row(
                              mainAxisAlignment:
                                  MainAxisAlignment.spaceBetween,
                              children: [
                                Column(
                                  crossAxisAlignment:
                                      CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      t('protection_active'),
                                      style: TextStyle(
                                        fontWeight: FontWeight.w600,
                                        fontSize: locale.bodySize,
                                        color: textPrimary,
                                      ),
                                    ),
                                    Text(
                                      t('tap_to_pause'),
                                      style: TextStyle(
                                        color: textSecondary,
                                        fontSize: locale.subtitleSize,
                                      ),
                                    ),
                                  ],
                                ),
                                Switch(
                                  value: _protectionActive,
                                  onChanged: (val) async {
                                    setState(
                                        () => _protectionActive = val);
                                    if (val) {
                                      await VpnChannel.startVpn();
                                    } else {
                                      await VpnChannel.stopVpn();
                                    }
                                  },
                                  activeColor: AppColors.accent,
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 16),

                    // ── Stats Row ──
                    Row(
                      children: [
                        Expanded(
                          child: _StatCard(
                            value: '$_safeCount',
                            label: t('safe_links_today'),
                            color: AppColors.safe,
                            isDark: isDark,
                            fontSize: locale.bodySize,
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: _StatCard(
                            value: '$_threatCount',
                            label: t('threats_blocked'),
                            color: AppColors.danger,
                            isDark: isDark,
                            fontSize: locale.bodySize,
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 16),

                    // ── Test Buttons ──
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: cardColor,
                        borderRadius: BorderRadius.circular(16),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black
                                .withOpacity(isDark ? 0.3 : 0.05),
                            blurRadius: 8,
                            offset: const Offset(0, 2),
                          ),
                        ],
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            t('recent_checks'),
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: locale.titleSize,
                              color: textPrimary,
                            ),
                          ),
                          const SizedBox(height: 12),

                          // Test dangerous
                          SizedBox(
                            width: double.infinity,
                            child: OutlinedButton.icon(
                              onPressed: _isChecking
                                  ? null
                                  : () => checkLink(
                                      'http://paypa1-verify.net/secure/login'),
                              icon: _isChecking
                                  ? const SizedBox(
                                      width: 16,
                                      height: 16,
                                      child: CircularProgressIndicator(
                                          strokeWidth: 2),
                                    )
                                  : const Icon(
                                      Icons.bug_report_outlined),
                              label: Text(
                                t('test_dangerous'),
                                style: TextStyle(
                                    fontSize: locale.bodySize),
                              ),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: AppColors.danger,
                                side: const BorderSide(
                                    color: AppColors.danger),
                                padding: const EdgeInsets.symmetric(
                                    vertical: 12),
                              ),
                            ),
                          ),

                          const SizedBox(height: 8),

                          // Test safe
                          SizedBox(
                            width: double.infinity,
                            child: OutlinedButton.icon(
                              onPressed: _isChecking
                                  ? null
                                  : () => checkLink(
                                      'https://www.google.com'),
                              icon: const Icon(
                                  Icons.check_circle_outline),
                              label: Text(
                                t('test_safe'),
                                style: TextStyle(
                                    fontSize: locale.bodySize),
                              ),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: AppColors.safe,
                                side: const BorderSide(
                                    color: AppColors.safe),
                                padding: const EdgeInsets.symmetric(
                                    vertical: 12),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 20),
                  ],
                ),
              ),
            ),

            const BottomNav(currentIndex: 0),
          ],
        ),
      ),
    );
  }
}

// ── Stat Card ──
class _StatCard extends StatelessWidget {
  final String value;
  final String label;
  final Color color;
  final bool isDark;
  final double fontSize;

  const _StatCard({
    required this.value,
    required this.label,
    required this.color,
    required this.isDark,
    required this.fontSize,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCard : AppColors.cardBg,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color:
                Colors.black.withOpacity(isDark ? 0.3 : 0.05),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            value,
            style: TextStyle(
              fontSize: 32,
              fontWeight: FontWeight.bold,
              color: color,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            label,
            style: TextStyle(
              color: isDark
                  ? AppColors.darkTextSecondary
                  : AppColors.textSecondary,
              fontSize: fontSize - 2,
            ),
          ),
        ],
      ),
    );
  }
}
