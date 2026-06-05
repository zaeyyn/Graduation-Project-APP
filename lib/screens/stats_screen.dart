import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:provider/provider.dart';
import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';
import '../widgets/bottom_nav.dart';
import '../services/history_service.dart';

class StatsScreen extends StatefulWidget {
  const StatsScreen({super.key});

  @override
  State<StatsScreen> createState() => _StatsScreenState();
}

class _StatsScreenState extends State<StatsScreen> {
  List<Map<String, dynamic>> _weekly = [];
  List<MapEntry<String, int>> _topBlocked = [];
  int _totalScanned = 0;
  int _totalSafe = 0;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final weekly = await HistoryService.getWeeklyStats();
    final topBlocked = await HistoryService.getTopBlocked();
    final history = await HistoryService.getHistory();
    final safe = history.where((e) => e.verdict == 'SAFE').length;

    if (mounted) {
      setState(() {
        _weekly = weekly;
        _topBlocked = topBlocked;
        _totalScanned = history.length;
        _totalSafe = safe;
      });
    }
  }

  String _dayLabel(DateTime dt) {
    // FIXED: removed unused `daysAr` variable
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    return days[dt.weekday % 7];
  }

  @override
  Widget build(BuildContext context) {
    final locale = context.watch<AppLocale>();
    // FIXED: use function declaration instead of variable assignment
    String t(String k) => AppTexts.get(k, locale.lang);
    final isAr = locale.isArabic;
    final isDark = locale.darkMode;
    final bgColor = isDark ? AppColors.darkBg : AppColors.background;
    final cardColor = isDark ? AppColors.darkCard : AppColors.cardBg;
    final textPrimary =
    isDark ? AppColors.darkTextPrimary : AppColors.textPrimary;
    final textSecondary =
    isDark ? AppColors.darkTextSecondary : AppColors.textSecondary;

    final safeRate = _totalScanned == 0
        ? 0
        : ((_totalSafe / _totalScanned) * 100).round();

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
                  t('stats'),
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: locale.headingSize,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),
            Expanded(
              child: RefreshIndicator(
                onRefresh: _load,
                child: ListView(
                  padding: const EdgeInsets.all(20),
                  children: [
                    // Summary cards
                    Row(
                      children: [
                        Expanded(
                          child: _SummaryCard(
                            label: t('total_scanned'),
                            value: '$_totalScanned',
                            icon: Icons.search,
                            color: AppColors.accent,
                            cardColor: cardColor,
                            textPrimary: textPrimary,
                            textSecondary: textSecondary,
                            isDark: isDark,
                            fontSize: locale.subtitleSize,
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: _SummaryCard(
                            label: t('safe_rate'),
                            value: '$safeRate%',
                            icon: Icons.shield_outlined,
                            color: AppColors.safe,
                            cardColor: cardColor,
                            textPrimary: textPrimary,
                            textSecondary: textSecondary,
                            isDark: isDark,
                            fontSize: locale.subtitleSize,
                          ),
                        ),
                      ],
                    ),

                    const SizedBox(height: 20),

                    // Weekly chart
                    Container(
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: cardColor,
                        borderRadius: BorderRadius.circular(20),
                        boxShadow: [
                          BoxShadow(
                            // FIXED: withOpacity → withValues
                            color: Colors.black
                                .withValues(alpha: isDark ? 0.3 : 0.06),
                            blurRadius: 12,
                            offset: const Offset(0, 4),
                          ),
                        ],
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            t('weekly_stats'),
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: locale.titleSize,
                              color: textPrimary,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Row(
                            children: [
                              _Legend(
                                  color: AppColors.safe,
                                  label: t('safe')),
                              const SizedBox(width: 16),
                              _Legend(
                                  color: AppColors.danger,
                                  label: t('danger')),
                            ],
                          ),
                          const SizedBox(height: 20),
                          SizedBox(
                            height: 180,
                            child: _weekly.isEmpty
                                ? Center(
                              child: Text(
                                t('no_data'),
                                style: TextStyle(
                                    color: textSecondary),
                              ),
                            )
                                : BarChart(
                              BarChartData(
                                alignment:
                                BarChartAlignment.spaceAround,
                                maxY: _weekly
                                    .map((e) =>
                                (e['safe'] as int) +
                                    (e['danger'] as int))
                                    .fold(0,
                                        (a, b) => a > b ? a : b)
                                    .toDouble() +
                                    2,
                                barTouchData:
                                BarTouchData(enabled: false),
                                titlesData: FlTitlesData(
                                  leftTitles: const AxisTitles(
                                    sideTitles: SideTitles(
                                        showTitles: false),
                                  ),
                                  rightTitles: const AxisTitles(
                                    sideTitles: SideTitles(
                                        showTitles: false),
                                  ),
                                  topTitles: const AxisTitles(
                                    sideTitles: SideTitles(
                                        showTitles: false),
                                  ),
                                  bottomTitles: AxisTitles(
                                    sideTitles: SideTitles(
                                      showTitles: true,
                                      getTitlesWidget: (val, _) {
                                        final idx = val.toInt();
                                        if (idx >= 0 &&
                                            idx < _weekly.length) {
                                          return Text(
                                            _dayLabel(_weekly[idx]
                                            ['day']),
                                            style: TextStyle(
                                              color: textSecondary,
                                              fontSize: 11,
                                            ),
                                          );
                                        }
                                        return const SizedBox();
                                      },
                                    ),
                                  ),
                                ),
                                gridData: FlGridData(
                                  drawVerticalLine: false,
                                  getDrawingHorizontalLine: (v) =>
                                      FlLine(
                                        color: isDark
                                            ? AppColors.darkDivider
                                            : AppColors.divider,
                                        strokeWidth: 1,
                                      ),
                                ),
                                borderData: FlBorderData(show: false),
                                barGroups: List.generate(
                                  _weekly.length,
                                      (i) => BarChartGroupData(
                                    x: i,
                                    barRods: [
                                      BarChartRodData(
                                        toY: (_weekly[i]['safe']
                                        as int)
                                            .toDouble(),
                                        color: AppColors.safe,
                                        width: 10,
                                        borderRadius:
                                        BorderRadius.circular(4),
                                      ),
                                      BarChartRodData(
                                        toY: (_weekly[i]['danger']
                                        as int)
                                            .toDouble(),
                                        color: AppColors.danger,
                                        width: 10,
                                        borderRadius:
                                        BorderRadius.circular(4),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 20),

                    // Top blocked
                    Container(
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: cardColor,
                        borderRadius: BorderRadius.circular(20),
                        boxShadow: [
                          BoxShadow(
                            // FIXED: withOpacity → withValues
                            color: Colors.black
                                .withValues(alpha: isDark ? 0.3 : 0.06),
                            blurRadius: 12,
                            offset: const Offset(0, 4),
                          ),
                        ],
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            t('top_blocked'),
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: locale.titleSize,
                              color: textPrimary,
                            ),
                          ),
                          const SizedBox(height: 14),
                          if (_topBlocked.isEmpty)
                            Center(
                              child: Padding(
                                padding:
                                const EdgeInsets.symmetric(vertical: 20),
                                child: Text(
                                  t('no_data'),
                                  style: TextStyle(color: textSecondary),
                                ),
                              ),
                            )
                          else
                            ..._topBlocked.asMap().entries.map((entry) {
                              final rank = entry.key + 1;
                              final domain = entry.value.key;
                              final count = entry.value.value;
                              final maxCount =
                              _topBlocked.first.value.toDouble();
                              return Padding(
                                padding: const EdgeInsets.only(bottom: 12),
                                child: Row(
                                  children: [
                                    Container(
                                      width: 28,
                                      height: 28,
                                      decoration: BoxDecoration(
                                        // FIXED: withOpacity → withValues
                                        color: AppColors.danger
                                            .withValues(alpha: 0.1),
                                        shape: BoxShape.circle,
                                      ),
                                      child: Center(
                                        child: Text(
                                          '$rank',
                                          style: const TextStyle(
                                            color: AppColors.danger,
                                            fontWeight: FontWeight.bold,
                                            fontSize: 12,
                                          ),
                                        ),
                                      ),
                                    ),
                                    const SizedBox(width: 10),
                                    Expanded(
                                      child: Column(
                                        crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                        children: [
                                          Text(
                                            domain,
                                            style: TextStyle(
                                              fontSize: locale.subtitleSize,
                                              fontWeight: FontWeight.w600,
                                              color: textPrimary,
                                            ),
                                          ),
                                          const SizedBox(height: 4),
                                          ClipRRect(
                                            borderRadius:
                                            BorderRadius.circular(4),
                                            child: LinearProgressIndicator(
                                              value: count / maxCount,
                                              minHeight: 6,
                                              // FIXED: withOpacity → withValues
                                              backgroundColor: AppColors
                                                  .danger
                                                  .withValues(alpha: 0.15),
                                              valueColor:
                                              const AlwaysStoppedAnimation(
                                                  AppColors.danger),
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),
                                    const SizedBox(width: 10),
                                    Text(
                                      '$count',
                                      style: TextStyle(
                                        color: AppColors.danger,
                                        fontWeight: FontWeight.bold,
                                        fontSize: locale.subtitleSize,
                                      ),
                                    ),
                                  ],
                                ),
                              );
                            }),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const BottomNav(currentIndex: 3),
          ],
        ),
      ),
    );
  }
}

class _SummaryCard extends StatelessWidget {
  final String label;
  final String value;
  final IconData icon;
  final Color color;
  final Color cardColor;
  final Color textPrimary;
  final Color textSecondary;
  final bool isDark;
  final double fontSize;

  const _SummaryCard({
    required this.label,
    required this.value,
    required this.icon,
    required this.color,
    required this.cardColor,
    required this.textPrimary,
    required this.textSecondary,
    required this.isDark,
    required this.fontSize,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            // FIXED: withOpacity → withValues
            color: Colors.black.withValues(alpha: isDark ? 0.3 : 0.05),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: color, size: 28),
          const SizedBox(height: 10),
          Text(
            value,
            style: TextStyle(
              fontSize: 28,
              fontWeight: FontWeight.bold,
              color: color,
            ),
          ),
          Text(
            label,
            style: TextStyle(
              color: textSecondary,
              fontSize: fontSize,
            ),
          ),
        ],
      ),
    );
  }
}

class _Legend extends StatelessWidget {
  final Color color;
  final String label;
  const _Legend({required this.color, required this.label});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          width: 12,
          height: 12,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 4),
        Text(label, style: const TextStyle(fontSize: 12)),
      ],
    );
  }
}