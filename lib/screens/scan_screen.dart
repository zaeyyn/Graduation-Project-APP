import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';
import '../widgets/bottom_nav.dart';
import '../services/api_service.dart';
import '../services/history_service.dart';
import '../services/whitelist_service.dart';
import '../models/link_entry.dart';
import 'danger_screen.dart';

class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  final TextEditingController _controller = TextEditingController();
  bool _scanning = false;
  LinkResult? _result;
  String _scannedUrl = '';

  Future<void> _scan() async {
    final url = _controller.text.trim();
    if (url.isEmpty) return;

    setState(() {
      _scanning = true;
      _result = null;
    });

    final isTrusted = await WhitelistService.isDomainTrusted(url);
    if (isTrusted) {
      setState(() {
        _scanning = false;
        _result = LinkResult(
          verdict: Verdict.safe,
          url: url,
          threatScore: 0,
          messageEn: 'This domain is in your trusted list.',
          messageAr: 'هذا النطاق في قائمتك الموثوقة.',
        );
        _scannedUrl = url;
      });
      return;
    }

    final result = await ApiService.checkUrl(url);
    final domain = Uri.tryParse(url)?.host ?? url;
    final verdictStr = result.verdict == Verdict.danger ? 'DANGER' : 'SAFE';

    await HistoryService.addEntry(LinkEntry(
      domain: domain,
      verdict: verdictStr,
      time: DateTime.now(),
    ));

    if (!mounted) return;
    setState(() {
      _scanning = false;
      _result = result;
      _scannedUrl = url;
    });
  }

  Color _verdictColor(Verdict v) {
    switch (v) {
      case Verdict.danger:
      case Verdict.unreachable:
        return AppColors.danger;
      case Verdict.safe:
        return AppColors.safe;
    }
  }

  IconData _verdictIcon(Verdict v) {
    switch (v) {
      case Verdict.danger:
      case Verdict.unreachable:
        return Icons.dangerous_outlined;
      case Verdict.safe:
        return Icons.check_circle_outline;
    }
  }

  String _verdictLabel(Verdict v, String lang) {
    switch (v) {
      case Verdict.danger:
        return lang == 'ar' ? 'خطر' : 'DANGER';
      case Verdict.unreachable:
        return lang == 'ar' ? 'تعذّر التحقق' : 'UNVERIFIED';
      case Verdict.safe:
        return lang == 'ar' ? 'آمن' : 'SAFE';
    }
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
                children: [
                  Text(
                    t('scan_link'),
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: locale.headingSize,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),

            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // ── Input card ──
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: cardColor,
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            t('enter_url'),
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: locale.titleSize,
                              color: textPrimary,
                            ),
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _controller,
                            textDirection: TextDirection.ltr,
                            decoration: InputDecoration(
                              hintText: 'https://example.com',
                              hintStyle: TextStyle(color: textSecondary),
                              filled: true,
                              fillColor: isDark
                                  ? AppColors.darkBg
                                  : AppColors.background,
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(12),
                                borderSide: BorderSide.none,
                              ),
                              suffixIcon: IconButton(
                                icon: const Icon(Icons.paste_outlined),
                                onPressed: () async {
                                  final data = await Clipboard.getData(
                                      Clipboard.kTextPlain);
                                  if (data?.text != null) {
                                    _controller.text = data!.text!;
                                  }
                                },
                              ),
                            ),
                          ),
                          const SizedBox(height: 12),
                          SizedBox(
                            width: double.infinity,
                            child: ElevatedButton.icon(
                              onPressed: _scanning ? null : _scan,
                              icon: _scanning
                                  ? const SizedBox(
                                      width: 18,
                                      height: 18,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                        color: Colors.white,
                                      ),
                                    )
                                  : const Icon(Icons.search),
                              label: Text(
                                _scanning
                                    ? t('checking')
                                    : t('check_link'),
                                style:
                                    TextStyle(fontSize: locale.bodySize),
                              ),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: AppColors.primary,
                                foregroundColor: Colors.white,
                                padding:
                                    const EdgeInsets.symmetric(vertical: 14),
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(12),
                                ),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 20),

                    // ── Result card ──
                    if (_result != null) ...[
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(20),
                        decoration: BoxDecoration(
                          color: cardColor,
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(
                            color: _verdictColor(_result!.verdict)
                                .withOpacity(0.4),
                            width: 1.5,
                          ),
                        ),
                        child: Column(
                          children: [
                            Icon(
                              _verdictIcon(_result!.verdict),
                              size: 56,
                              color: _verdictColor(_result!.verdict),
                            ),
                            const SizedBox(height: 12),
                            Text(
                              _verdictLabel(_result!.verdict, locale.lang),
                              style: TextStyle(
                                fontSize: 22,
                                fontWeight: FontWeight.bold,
                                color: _verdictColor(_result!.verdict),
                              ),
                            ),
                            const SizedBox(height: 8),
                            Text(
                              locale.lang == 'ar'
                                  ? _result!.messageAr
                                  : _result!.messageEn,
                              textAlign: TextAlign.center,
                              style: TextStyle(
                                color: textSecondary,
                                fontSize: locale.bodySize,
                              ),
                            ),
                            const SizedBox(height: 16),
                            // Score bar
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Row(
                                  mainAxisAlignment:
                                      MainAxisAlignment.spaceBetween,
                                  children: [
                                    Text(
                                      t('threat_score'),
                                      style: TextStyle(
                                        color: textSecondary,
                                        fontSize: locale.subtitleSize,
                                      ),
                                    ),
                                    Text(
                                      '${_result!.threatScore.toStringAsFixed(1)}%',
                                      style: TextStyle(
                                        fontWeight: FontWeight.bold,
                                        color: _verdictColor(_result!.verdict),
                                        fontSize: locale.subtitleSize,
                                      ),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 6),
                                ClipRRect(
                                  borderRadius: BorderRadius.circular(8),
                                  child: LinearProgressIndicator(
                                    value: _result!.threatScore / 100,
                                    minHeight: 8,
                                    backgroundColor: isDark
                                        ? AppColors.darkBg
                                        : AppColors.background,
                                    valueColor: AlwaysStoppedAnimation(
                                      _verdictColor(_result!.verdict),
                                    ),
                                  ),
                                ),
                              ],
                            ),
                            if (_result!.verdict == Verdict.danger ||
                                _result!.verdict == Verdict.unreachable) ...[
                              const SizedBox(height: 16),
                              SizedBox(
                                width: double.infinity,
                                child: ElevatedButton.icon(
                                  onPressed: () {
                                    Navigator.push(
                                      context,
                                      MaterialPageRoute(
                                        builder: (_) => DangerScreen(
                                          url: _scannedUrl,
                                          threatScore: _result!.threatScore,
                                        ),
                                      ),
                                    );
                                  },
                                  icon: const Icon(Icons.warning_amber),
                                  label: Text(t('view_details')),
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: AppColors.danger,
                                    foregroundColor: Colors.white,
                                    shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(12),
                                    ),
                                  ),
                                ),
                              ),
                            ],
                          ],
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),

            const BottomNav(currentIndex: 1),
          ],
        ),
      ),
    );
  }
}