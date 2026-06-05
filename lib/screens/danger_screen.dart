import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';

class DangerScreen extends StatelessWidget {
  final String url;
  final double threatScore;

  const DangerScreen({
    super.key,
    required this.url,
    required this.threatScore,
  });

  @override
  Widget build(BuildContext context) {
    final locale = context.watch<AppLocale>();
    // FIXED: use function declaration instead of variable assignment
    String t(String k) => AppTexts.get(k, locale.lang);
    final isAr = locale.isArabic;
    final domain = Uri.tryParse(url)?.host ?? url;

    // FIXED: threatScore is already 0–100 from the API (e.g. 98.6)
    // so we just round it directly instead of multiplying by 100 again
    final percent = threatScore.toInt().clamp(0, 100);

    // FIXED: progress bar also needs 0.0–1.0 range, so divide by 100
    final progressValue = (threatScore / 100).clamp(0.0, 1.0);

    return Directionality(
      textDirection: isAr ? TextDirection.rtl : TextDirection.ltr,
      child: Scaffold(
        backgroundColor: AppColors.danger,
        body: SafeArea(
          child: Padding(
            padding:
            const EdgeInsets.symmetric(horizontal: 28, vertical: 32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Spacer(),

                // Warning icon
                Container(
                  width: 110,
                  height: 110,
                  decoration: BoxDecoration(
                    // FIXED: withOpacity → withValues
                    color: Colors.white.withValues(alpha: 0.15),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(
                    Icons.warning_rounded,
                    color: Color(0xFFFFC107),
                    size: 62,
                  ),
                ),
                const SizedBox(height: 28),

                // Title
                Text(
                  t('danger_title'),
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: locale.headingSize + 6,
                    fontWeight: FontWeight.bold,
                    height: 1.2,
                  ),
                ),
                const SizedBox(height: 10),
                Text(
                  t('danger_subtitle'),
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    // FIXED: withOpacity → withValues
                    color: Colors.white.withValues(alpha: 0.85),
                    fontSize: locale.bodySize + 2,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 20),

                // Body
                Text(
                  t('danger_body'),
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    // FIXED: withOpacity → withValues
                    color: Colors.white.withValues(alpha: 0.8),
                    fontSize: locale.bodySize,
                    height: 1.5,
                  ),
                ),

                const SizedBox(height: 28),

                // Blocked URL box
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    // FIXED: withOpacity → withValues
                    color: Colors.white.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                      // FIXED: withOpacity → withValues
                        color: Colors.white.withValues(alpha: 0.2)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        t('blocked_link'),
                        style: TextStyle(
                          // FIXED: withOpacity → withValues
                          color: Colors.white.withValues(alpha: 0.7),
                          fontSize: locale.subtitleSize,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        domain,
                        textDirection: TextDirection.ltr,
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: locale.bodySize,
                          fontWeight: FontWeight.w500,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 20),

                // Threat level bar
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          t('threat_level'),
                          style: TextStyle(
                            // FIXED: withOpacity → withValues
                            color: Colors.white.withValues(alpha: 0.8),
                            fontSize: locale.subtitleSize,
                          ),
                        ),
                        Text(
                          '$percent%',
                          style: TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: locale.subtitleSize,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(6),
                      child: LinearProgressIndicator(
                        // FIXED: use progressValue (0.0–1.0) not raw threatScore
                        value: progressValue,
                        minHeight: 10,
                        // FIXED: withOpacity → withValues
                        backgroundColor:
                        Colors.white.withValues(alpha: 0.25),
                        valueColor: const AlwaysStoppedAnimation<Color>(
                            Colors.white),
                      ),
                    ),
                  ],
                ),

                const Spacer(),

                // Go Back button
                SizedBox(
                  width: double.infinity,
                  height: 58,
                  child: ElevatedButton(
                    onPressed: () => Navigator.pop(context),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.white,
                      foregroundColor: AppColors.danger,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(16),
                      ),
                      elevation: 0,
                    ),
                    child: Text(
                      t('go_back'),
                      style: TextStyle(
                        fontSize: locale.buttonSize,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
              ],
            ),
          ),
        ),
      ),
    );
  }
}