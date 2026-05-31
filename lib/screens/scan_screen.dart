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

    if (mounted) {
      setState(() {
        _scanning = false;
        _result = result;
        _scannedUrl = url;
      });

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
      }
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
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

    Color resultColor = AppColors.safe;
    IconData resultIcon = Icons.check_circle;
    String resultLabel = '';

    if (_result != null) {
      if (_result!.verdict == Verdict.danger) {
        resultColor = AppColors.danger;
        resultIcon = Icons.dangerous_rounded;
        resultLabel = t('danger');
      } else if (_result!.verdict == Verdict.warning) {
        resultColor = AppColors.warning;
        resultIcon = Icons.warning_rounded;
        resultLabel = t('warn');
      } else {
        resultColor = AppColors.safe;
        resultIcon = Icons.check_circle_rounded;
        resultLabel = t('safe');
      }
    }

    return Directionality(
      textDirection: isAr ? TextDirection.rtl : TextDirection.ltr,
      child: Scaffold(
        backgroundColor: bgColor,
        body: Column(
          children: [
            Container(
              color: AppColors.primary,
              padding: EdgeInsets.only(
                top: MediaQuery.of(context).padding.top + 16,
                bottom: 20,
                left: 24,
                right: 24,
              ),
              child: Align(
                alignment:
                    isAr ? Alignment.centerRight : Alignment.centerLeft,
                child: Text(
                  t('manual_scan'),
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: locale.headingSize,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Column(
                  children: [
                    // Input card
                    Container(
                      padding: const EdgeInsets.all(20),
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
                          TextField(
                            controller: _controller,
                            textDirection: TextDirection.ltr,
                            decoration: InputDecoration(
                              hintText: t('paste_link'),
                              hintStyle:
                                  TextStyle(color: textSecondary),
                              prefixIcon: const Icon(Icons.link,
                                  color: AppColors.accent),
                              suffixIcon: IconButton(
                                icon: const Icon(Icons.content_paste,
                                    color: AppColors.accent),
                                onPressed: () async {
                                  final data = await Clipboard.getData(
                                      'text/plain');
                                  if (data?.text != null) {
                                    _controller.text = data!.text!;
                                  }
                                },
                                tooltip: 'Paste',
                              ),
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(14),
                                borderSide: BorderSide(
                                    color: isDark
                                        ? AppColors.darkDivider
                                        : AppColors.divider),
                              ),
                              focusedBorder: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(14),
                                borderSide: const BorderSide(
                                    color: AppColors.accent, width: 2),
                              ),
                              filled: true,
                              fillColor: isDark
                                  ? AppColors.darkBg
                                  : AppColors.background,
                            ),
                            style: TextStyle(color: textPrimary),
                          ),
                          const SizedBox(height: 14),
                          SizedBox(
                            width: double.infinity,
                            height: 52,
                            child: ElevatedButton.icon(
                              onPressed: _scanning ? null : _scan,
                              icon: _scanning
                                  ? const SizedBox(
                                      width: 20,
                                      height: 20,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                        color: Colors.white,
                                      ),
                                    )
                                  : const Icon(Icons.search,
                                      color: Colors.white),
                              label: Text(
                                _scanning
                                    ? t('scanning')
                                    : t('scan_now'),
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: locale.buttonSize,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: AppColors.primary,
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(14),
                                ),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),

                    // Result card
                    if (_result != null) ...[
                      const SizedBox(height: 20),
                      AnimatedContainer(
                        duration: const Duration(milliseconds: 400),
                        curve: Curves.easeOut,
                        width: double.infinity,
                        padding: const EdgeInsets.all(24),
                        decoration: BoxDecoration(
                          color: resultColor.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(20),
                          border:
                              Border.all(color: resultColor, width: 2),
                        ),
                        child: Column(
                          children: [
                            Icon(resultIcon,
                                color: resultColor, size: 56),
                            const SizedBox(height: 12),
                            Text(
                              resultLabel,
                              style: TextStyle(
                                color: resultColor,
                                fontSize: locale.titleSize + 4,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 8),
                            Text(
                              isAr
                                  ? _result!.messageAr
                                  : _result!.messageEn,
                              textAlign: TextAlign.center,
                              style: TextStyle(
                                color: textSecondary,
                                fontSize: locale.bodySize,
                              ),
                            ),
                            if (_result!.threatScore > 0) ...[
                              const SizedBox(height: 14),
                              Row(
                                mainAxisAlignment:
                                    MainAxisAlignment.spaceBetween,
                                children: [
                                  Text(
                                    t('threat_level'),
                                    style: TextStyle(
                                        color: textSecondary,
                                        fontSize: locale.subtitleSize),
                                  ),
                                  Text(
                                    '${(_result!.threatScore * 100).toInt()}%',
                                    style: TextStyle(
                                      color: resultColor,
                                      fontWeight: FontWeight.bold,
                                      fontSize: locale.subtitleSize,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 6),
                              ClipRRect(
                                borderRadius: BorderRadius.circular(6),
                                child: LinearProgressIndicator(
                                  value: _result!.threatScore
                                      .clamp(0.0, 1.0),
                                  minHeight: 8,
                                  backgroundColor:
                                      resultColor.withOpacity(0.2),
                                  valueColor:
                                      AlwaysStoppedAnimation(resultColor),
                                ),
                              ),
                            ],
                            const SizedBox(height: 12),
                            // URL
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 12, vertical: 8),
                              decoration: BoxDecoration(
                                color: resultColor.withOpacity(0.08),
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: Text(
                                _scannedUrl,
                                textDirection: TextDirection.ltr,
                                style: TextStyle(
                                  color: textSecondary,
                                  fontSize: 12,
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],

                    const SizedBox(height: 20),

                    // Whitelist section
                    _WhitelistSection(
                      locale: locale,
                      isDark: isDark,
                      cardColor: cardColor,
                      textPrimary: textPrimary,
                      textSecondary: textSecondary,
                    ),
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

class _WhitelistSection extends StatefulWidget {
  final AppLocale locale;
  final bool isDark;
  final Color cardColor;
  final Color textPrimary;
  final Color textSecondary;

  const _WhitelistSection({
    required this.locale,
    required this.isDark,
    required this.cardColor,
    required this.textPrimary,
    required this.textSecondary,
  });

  @override
  State<_WhitelistSection> createState() => _WhitelistSectionState();
}

class _WhitelistSectionState extends State<_WhitelistSection> {
  List<String> _list = [];
  final TextEditingController _wlController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final list = await WhitelistService.getWhitelist();
    if (mounted) setState(() => _list = list);
  }

  Future<void> _add() async {
    await WhitelistService.addDomain(_wlController.text);
    _wlController.clear();
    await _load();
  }

  Future<void> _remove(String domain) async {
    await WhitelistService.removeDomain(domain);
    await _load();
  }

  @override
  void dispose() {
    _wlController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final locale = widget.locale;
    final t = (String k) => AppTexts.get(k, locale.lang);
    final isAr = locale.isArabic;

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: widget.cardColor,
        borderRadius: BorderRadius.circular(20),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(widget.isDark ? 0.3 : 0.06),
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.verified_outlined,
                  color: AppColors.safe, size: 22),
              const SizedBox(width: 8),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      t('whitelist'),
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: locale.bodySize + 1,
                        color: widget.textPrimary,
                      ),
                    ),
                    Text(
                      t('whitelist_sub'),
                      style: TextStyle(
                        color: widget.textSecondary,
                        fontSize: locale.subtitleSize,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _wlController,
                  textDirection: TextDirection.ltr,
                  decoration: InputDecoration(
                    hintText: t('whitelist_hint'),
                    hintStyle: TextStyle(color: widget.textSecondary),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: BorderSide(
                          color: widget.isDark
                              ? AppColors.darkDivider
                              : AppColors.divider),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(
                          color: AppColors.safe, width: 2),
                    ),
                    filled: true,
                    fillColor: widget.isDark
                        ? AppColors.darkBg
                        : AppColors.background,
                    isDense: true,
                    contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                  ),
                  style: TextStyle(color: widget.textPrimary, fontSize: 14),
                ),
              ),
              const SizedBox(width: 8),
              ElevatedButton(
                onPressed: _add,
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.safe,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12)),
                  padding: const EdgeInsets.symmetric(
                      horizontal: 16, vertical: 12),
                ),
                child: Text(
                  t('add'),
                  style: const TextStyle(
                      color: Colors.white, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          if (_list.isNotEmpty) ...[
            const SizedBox(height: 12),
            ..._list.map((domain) => Container(
                  margin: const EdgeInsets.only(bottom: 8),
                  padding: const EdgeInsets.symmetric(
                      horizontal: 12, vertical: 10),
                  decoration: BoxDecoration(
                    color: AppColors.safe.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                        color: AppColors.safe.withOpacity(0.3)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.check_circle,
                          color: AppColors.safe, size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          domain,
                          style: TextStyle(
                            color: widget.textPrimary,
                            fontSize: locale.subtitleSize,
                          ),
                        ),
                      ),
                      GestureDetector(
                        onTap: () => _remove(domain),
                        child: const Icon(Icons.close,
                            color: AppColors.danger, size: 18),
                      ),
                    ],
                  ),
                )),
          ],
        ],
      ),
    );
  }
}