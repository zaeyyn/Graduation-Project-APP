import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:telephony/telephony.dart';

import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';

class DangerScreen extends StatefulWidget {
  final String url;
  final double threatScore;

  const DangerScreen({
    super.key,
    required this.url,
    required this.threatScore,
  });

  @override
  State<DangerScreen> createState() => _DangerScreenState();
}

class _DangerScreenState extends State<DangerScreen> {
  final Telephony _telephony = Telephony.instance;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _sendFamilySms();
    });
  }

  Future<void> _sendFamilySms() async {
    final prefs = await SharedPreferences.getInstance();

    final notifyFamily = prefs.getBool('notifyFamily') ?? false;
    if (!notifyFamily) return;

    final familyPhone = prefs.getString('family_phone') ?? '';
    if (familyPhone.isEmpty) return;

    final domain = Uri.tryParse(widget.url)?.host ?? widget.url;
    // threatScore is already 0–100, so just round/clamp it directly
    final percent = widget.threatScore.toInt().clamp(0, 100);

    final message =
        '⚠️ LinkGuard Alert\n'
        'A dangerous link was detected on this device.\n'
        'Link: $domain\n'
        'Threat level: $percent%\n\n'
        '⚠️ تنبيه LinkGuard\n'
        'تم اكتشاف رابط خطير على هذا الجهاز.\n'
        'الرابط: $domain\n'
        'مستوى الخطر: $percent%';

    try {
      final permissionGranted = await _telephony.requestPhoneAndSmsPermissions;

      if (permissionGranted == true) {
        await _telephony.sendSms(
          to: familyPhone,
          message: message,
          isMultipart: true,
        );
      }
    } catch (e) {
      debugPrint('SMS send failed: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final locale = context.watch<AppLocale>();
    String t(String k) => AppTexts.get(k, locale.lang);
    final isAr = locale.isArabic;
    final domain = Uri.tryParse(widget.url)?.host ?? widget.url;

    final percent = widget.threatScore.toInt().clamp(0, 100);
    final progressValue = (widget.threatScore / 100).clamp(0.0, 1.0);

    return Directionality(
      textDirection: isAr ? TextDirection.rtl : TextDirection.ltr,
      child: Scaffold(
        backgroundColor: AppColors.danger,
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Spacer(),
                Container(
                  width: 110,
                  height: 110,
                  decoration: BoxDecoration(
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
                    color: Colors.white.withValues(alpha: 0.85),
                    fontSize: locale.bodySize + 2,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 20),
                Text(
                  t('danger_body'),
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white.withValues(alpha: 0.8),
                    fontSize: locale.bodySize,
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 28),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.2)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        t('blocked_link'),
                        style: TextStyle(
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
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          t('threat_level'),
                          style: TextStyle(
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
                        value: progressValue,
                        minHeight: 10,
                        backgroundColor: Colors.white.withValues(alpha: 0.25),
                        valueColor: const AlwaysStoppedAnimation<Color>(Colors.white),
                      ),
                    ),
                  ],
                ),
                const Spacer(),
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