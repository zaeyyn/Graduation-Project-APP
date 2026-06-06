import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';
import '../widgets/bottom_nav.dart';
import '../services/history_service.dart';
import '../services/api_service.dart';
import '../services/whitelist_service.dart';
import '../models/link_entry.dart';
import 'danger_screen.dart';
import '../services/vpn_service.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  // Start as FALSE so user must explicitly turn it ON
  // This ensures VPN permission dialog is shown on first tap
  bool _protectionActive = false;
  int _safeCount = 0;
  int _threatCount = 0;
  bool _isChecking = false;

  @override
  void initState() {
    super.initState();
    _loadStats();
    VpnChannel.listenForLinks(
      (url) {
        checkLink(url);
      },
      onDangerDetected: (url, score) {
        if (!mounted) return;
        Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) => DangerScreen(
              url: url,
              threatScore: score,
            ),
          ),
        );
      },
    );
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

  Future<void> _toggleVpn(bool val) async {
    setState(() => _protectionActive = val);
    if (val) {
      try {
        debugPrint('Calling startVpn...');
        await VpnChannel.startVpn();
        debugPrint('startVpn called successfully');
      } catch (e) {
        debugPrint('startVpn error: $e');
        if (mounted) {
          setState(() => _protectionActive = false);
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Could not start VPN: $e')),
          );
        }
      }
    } else {
      try {
        debugPrint('Calling stopVpn...');
        await VpnChannel.stopVpn();
        debugPrint('stopVpn called successfully');
      } catch (e) {
        debugPrint('stopVpn error: $e');
      }
    }
  }

  Future<void> checkLink(String url) async {
    if (!_protectionActive || _isChecking) return;

    try {
      final isTrusted = await WhitelistService.isDomainTrusted(url);

      if (!mounted) return;

      if (isTrusted) {
        _showSafeSnackbar(
          context.read<AppLocale>().lang,
          trusted: true,
        );
        return;
      }

      setState(() => _isChecking = true);

      final result = await ApiService.checkUrl(url);
      debugPrint("URL: $url");
      debugPrint("Verdict: ${result.verdict}");
      debugPrint("Threat score: ${result.threatScore}");

      if (!mounted) return;

      final locale = context.read<AppLocale>();
      final domain = Uri.tryParse(url)?.host ?? url;

      final verdictStr =
          result.verdict == Verdict.danger ? 'DANGER' : 'SAFE';

      await HistoryService.addEntry(
        LinkEntry(
          domain: domain,
          verdict: verdictStr,
          time: DateTime.now(),
        ),
      );

      await _loadStats();

      if (!mounted) return;

      if (result.verdict == Verdict.danger ||
          result.verdict == Verdict.unreachable) {
        await Navigator.push(
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
    } catch (e) {
      debugPrint('API error: $e');

      if (!mounted) return;

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Failed to check URL: $e'),
        ),
      );
    } finally {
      if (mounted) {
        setState(() => _isChecking = false);
      }
    }
  }

  void _showSafeSnackbar(String lang, {bool trusted = false}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: trusted ? AppColors.primaryLight : AppColors.safe,
        behavior: SnackBarBehavior.floating,
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
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
                        ? (lang == 'ar' ? 'موقع موثوق ✓' : 'Trusted website ✓')
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
                      color: Colors.white.withValues(alpha: 0.9),
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
    String t(String k) => AppTexts.get(k, locale.lang);
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
                          color: Colors.white.withValues(alpha: 0.8),
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
                  GestureDetector(
                    onTap: () => locale.setLang(isAr ? 'en' : 'ar'),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 14, vertical: 7),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(
                            color: Colors.white.withValues(alpha: 0.3)),
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
                    // ── Protection card ──
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(24),
                      decoration: BoxDecoration(
                        color: cardColor,
                        borderRadius: BorderRadius.circular(20),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black
                                .withValues(alpha: isDark ? 0.3 : 0.06),
                            blurRadius: 12,
                            offset: const Offset(0, 4),
                          ),
                        ],
                      ),
                      child: Column(
                        children: [
                          Container(
                            width: 80,
                            height: 80,
                            decoration: BoxDecoration(
                              color: _protectionActive
                                  ? AppColors.accent.withValues(alpha: 0.1)
                                  : Colors.grey.withValues(alpha: 0.1),
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
                            _protectionActive
                                ? t('you_are_protected')
                                : (isAr ? 'الحماية متوقفة' : 'Protection Off'),
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: locale.titleSize,
                              color: textPrimary,
                            ),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            _protectionActive
                                ? t('all_links_checked')
                                : (isAr
                                    ? 'اضغط للتفعيل'
                                    : 'Tap to enable protection'),
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: textSecondary,
                              fontSize: locale.subtitleSize,
                            ),
                          ),
                          const SizedBox(height: 20),
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
                                      _protectionActive
                                          ? t('protection_active')
                                          : (isAr
                                              ? 'الحماية غير مفعّلة'
                                              : 'Protection inactive'),
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
                                  onChanged: _toggleVpn,
                                  activeThumbColor: AppColors.accent,
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 16),

                    // ── Stats row ──
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

                    // ── Test buttons ──
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: cardColor,
                        borderRadius: BorderRadius.circular(16),
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
                                  : const Icon(Icons.bug_report_outlined),
                              label: Text(
                                'Test Dangerous Link',
                                style: TextStyle(fontSize: locale.bodySize),
                              ),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: AppColors.danger,
                                side: const BorderSide(
                                    color: AppColors.danger),
                              ),
                            ),
                          ),
                          const SizedBox(height: 8),
                          SizedBox(
                            width: double.infinity,
                            child: OutlinedButton.icon(
                              onPressed: _isChecking
                                  ? null
                                  : () =>
                                      checkLink('https://www.google.com'),
                              icon: const Icon(Icons.check_circle_outline),
                              label: Text(
                                'Test Safe Link',
                                style: TextStyle(fontSize: locale.bodySize),
                              ),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: AppColors.safe,
                                side:
                                    const BorderSide(color: AppColors.safe),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
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
            color: Colors.black.withValues(alpha: isDark ? 0.3 : 0.05),
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