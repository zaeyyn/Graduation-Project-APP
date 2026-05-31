import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';
import '../widgets/bottom_nav.dart';
import '../services/history_service.dart';
import '../models/link_entry.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  List<LinkEntry> _entries = [];
  final Set<int> _selected = {};
  bool _selectionMode = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final list = await HistoryService.getHistory();
    if (mounted) setState(() => _entries = list);
  }

  void _toggleSelect(int index) {
    setState(() {
      if (_selected.contains(index)) {
        _selected.remove(index);
        if (_selected.isEmpty) _selectionMode = false;
      } else {
        _selected.add(index);
      }
    });
  }

  void _toggleSelectAll() {
    setState(() {
      if (_selected.length == _entries.length) {
        _selected.clear();
        _selectionMode = false;
      } else {
        _selected.addAll(List.generate(_entries.length, (i) => i));
      }
    });
  }

  Future<void> _deleteSelected() async {
    final toDelete = _selected.map((i) => _entries[i]).toList();
    await HistoryService.deleteEntries(toDelete);
    setState(() {
      _selected.clear();
      _selectionMode = false;
    });
    await _load();
  }

  Future<void> _clearAll(AppLocale locale) async {
    final isAr = locale.isArabic;
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(
          AppTexts.get('confirm_clear', locale.lang),
          style: TextStyle(
            fontWeight: FontWeight.bold,
            fontSize: locale.titleSize,
            color: AppColors.textPrimary,
          ),
        ),
        content: Text(
          AppTexts.get('confirm_clear_body', locale.lang),
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: locale.bodySize,
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text(
              AppTexts.get('cancel', locale.lang),
              style: TextStyle(
                color: AppColors.textSecondary,
                fontSize: locale.bodySize,
              ),
            ),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.danger,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10)),
            ),
            child: Text(
              AppTexts.get('clear_all', locale.lang),
              style: TextStyle(
                color: Colors.white,
                fontSize: locale.bodySize,
              ),
            ),
          ),
        ],
      ),
    );
    if (confirm == true) {
      await HistoryService.clearAll();
      await _load();
    }
  }

  Color _verdictColor(String verdict) {
    if (verdict == 'DANGER') return AppColors.danger;
    if (verdict == 'WARN') return AppColors.warning;
    return AppColors.safe;
  }

  String _formatTime(DateTime dt) {
    final now = DateTime.now();
    final diff = now.difference(dt);
    final h = dt.hour.toString().padLeft(2, '0');
    final m = dt.minute.toString().padLeft(2, '0');
    final ampm = dt.hour < 12 ? 'AM' : 'PM';
    if (diff.inDays == 0) return 'Today, $h:$m $ampm';
    if (diff.inDays == 1) return 'Yesterday, $h:$m $ampm';
    return '${dt.day}/${dt.month}/${dt.year}';
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
                bottom: 16,
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
                        t('link_history'),
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: locale.headingSize,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        t('last_50'),
                        style: TextStyle(
                          color: Colors.white.withOpacity(0.75),
                          fontSize: locale.subtitleSize,
                        ),
                      ),
                    ],
                  ),
                  if (_entries.isNotEmpty)
                    GestureDetector(
                      onTap: () => _clearAll(locale),
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 6),
                        decoration: BoxDecoration(
                          color: AppColors.danger.withOpacity(0.2),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                              color: Colors.white.withOpacity(0.3)),
                        ),
                        child: Text(
                          t('clear_all'),
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: locale.subtitleSize,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ),

            // ── Selection toolbar ──
            if (_selectionMode)
              Container(
                color: AppColors.primaryLight,
                padding: const EdgeInsets.symmetric(
                    horizontal: 16, vertical: 10),
                child: Row(
                  children: [
                    Text(
                      '${_selected.length} ${t('selected')}',
                      style: TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: locale.bodySize,
                      ),
                    ),
                    const Spacer(),
                    TextButton.icon(
                      onPressed: _toggleSelectAll,
                      icon: Icon(
                        _selected.length == _entries.length
                            ? Icons.deselect
                            : Icons.select_all,
                        color: Colors.white,
                        size: 20,
                      ),
                      label: Text(
                        _selected.length == _entries.length
                            ? t('deselect_all')
                            : t('select_all'),
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: locale.subtitleSize,
                        ),
                      ),
                    ),
                    const SizedBox(width: 6),
                    ElevatedButton.icon(
                      onPressed:
                          _selected.isEmpty ? null : _deleteSelected,
                      icon: const Icon(Icons.delete_outline,
                          size: 18, color: Colors.white),
                      label: Text(
                        t('delete'),
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: locale.subtitleSize,
                        ),
                      ),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.danger,
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10)),
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 6),
                      ),
                    ),
                    IconButton(
                      onPressed: () => setState(() {
                        _selected.clear();
                        _selectionMode = false;
                      }),
                      icon: const Icon(Icons.close, color: Colors.white),
                    ),
                  ],
                ),
              ),

            // ── List ──
            Expanded(
              child: _entries.isEmpty
                  ? Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            Icons.history,
                            size: 64,
                            color: textSecondary.withOpacity(0.4),
                          ),
                          const SizedBox(height: 12),
                          Text(
                            isAr
                                ? 'لا يوجد روابط محفوظة'
                                : 'No links checked yet',
                            style: TextStyle(
                              color: textSecondary.withOpacity(0.6),
                              fontSize: locale.bodySize,
                            ),
                          ),
                        ],
                      ),
                    )
                  : ListView.separated(
                      padding: const EdgeInsets.all(16),
                      itemCount: _entries.length,
                      separatorBuilder: (_, __) =>
                          const SizedBox(height: 10),
                      itemBuilder: (context, index) {
                        final entry = _entries[index];
                        final color = _verdictColor(entry.verdict);
                        final isSelected = _selected.contains(index);
                        final verdictLabel = AppTexts.get(
                          entry.verdict.toLowerCase(),
                          locale.lang,
                        );

                        return GestureDetector(
                          onLongPress: () => setState(() {
                            _selectionMode = true;
                            _selected.add(index);
                          }),
                          onTap: _selectionMode
                              ? () => _toggleSelect(index)
                              : null,
                          child: AnimatedContainer(
                            duration: const Duration(milliseconds: 200),
                            padding: const EdgeInsets.symmetric(
                                horizontal: 16, vertical: 14),
                            decoration: BoxDecoration(
                              color: isSelected
                                  ? AppColors.accent.withOpacity(0.1)
                                  : cardColor,
                              borderRadius: BorderRadius.circular(14),
                              border: Border.all(
                                color: isSelected
                                    ? AppColors.accent
                                    : Colors.transparent,
                                width: 2,
                              ),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withOpacity(
                                      isDark ? 0.3 : 0.04),
                                  blurRadius: 6,
                                  offset: const Offset(0, 2),
                                ),
                              ],
                            ),
                            child: Row(
                              children: [
                                // Dot or checkbox
                                if (_selectionMode)
                                  Icon(
                                    isSelected
                                        ? Icons.check_circle
                                        : Icons.radio_button_unchecked,
                                    color: isSelected
                                        ? AppColors.accent
                                        : textSecondary,
                                    size: 22,
                                  )
                                else
                                  Container(
                                    width: 12,
                                    height: 12,
                                    decoration: BoxDecoration(
                                      color: color,
                                      shape: BoxShape.circle,
                                    ),
                                  ),
                                const SizedBox(width: 12),
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        entry.domain,
                                        style: TextStyle(
                                          fontWeight: FontWeight.w600,
                                          fontSize: locale.bodySize,
                                          color: textPrimary,
                                        ),
                                      ),
                                      const SizedBox(height: 2),
                                      Text(
                                        _formatTime(entry.time),
                                        style: TextStyle(
                                          color: textSecondary,
                                          fontSize: locale.subtitleSize,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                                Container(
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 10, vertical: 4),
                                  decoration: BoxDecoration(
                                    color: color.withOpacity(0.12),
                                    borderRadius:
                                        BorderRadius.circular(8),
                                    border: Border.all(
                                        color: color.withOpacity(0.3)),
                                  ),
                                  child: Text(
                                    verdictLabel,
                                    style: TextStyle(
                                      color: color,
                                      fontWeight: FontWeight.bold,
                                      fontSize: locale.subtitleSize,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        );
                      },
                    ),
            ),

            const BottomNav(currentIndex: 2),
          ],
        ),
      ),
    );
  }
}