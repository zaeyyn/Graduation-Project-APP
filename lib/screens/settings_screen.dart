import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';
import '../widgets/bottom_nav.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final TextEditingController _phoneController = TextEditingController();
  String _savedPhone = '';
  bool _protectionActive = true;

  @override
  void initState() {
    super.initState();
    _loadPhone();
  }

  Future<void> _loadPhone() async {
    final prefs = await SharedPreferences.getInstance();
    final phone = prefs.getString('family_phone') ?? '';
    setState(() {
      _savedPhone = phone;
      _phoneController.text = phone;
    });
  }

  Future<void> _savePhone(String phone) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('family_phone', phone);
    setState(() => _savedPhone = phone);
  }

  void _showPhoneDialog(BuildContext context, AppLocale locale) {
    final t = (String k) => AppTexts.get(k, locale.lang);
    final isAr = locale.isArabic;
    final isDark = locale.darkMode;

    showDialog(
      context: context,
      builder: (ctx) => Directionality(
        textDirection: isAr ? TextDirection.rtl : TextDirection.ltr,
        child: AlertDialog(
          backgroundColor:
              isDark ? AppColors.darkCard : Colors.white,
          shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(20)),
          title: Text(
            t('family_number'),
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: locale.titleSize,
              color: isDark
                  ? AppColors.darkTextPrimary
                  : AppColors.textPrimary,
            ),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                isAr
                    ? 'أدخل رقم هاتف أحد أفراد العائلة ليتلقى إشعاراً عند اكتشاف رابط خطير'
                    : 'Enter a family member\'s phone number to notify them when a dangerous link is detected.',
                style: TextStyle(
                  color: isDark
                      ? AppColors.darkTextSecondary
                      : AppColors.textSecondary,
                  fontSize: locale.subtitleSize,
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _phoneController,
                keyboardType: TextInputType.phone,
                inputFormatters: [
                  FilteringTextInputFormatter.allow(
                      RegExp(r'[0-9+]'))
                ],
                textDirection: TextDirection.ltr,
                style: TextStyle(
                  color: isDark
                      ? AppColors.darkTextPrimary
                      : AppColors.textPrimary,
                  fontSize: locale.bodySize,
                ),
                decoration: InputDecoration(
                  hintText: '+962 7X XXX XXXX',
                  hintStyle: TextStyle(
                    color: isDark
                        ? AppColors.darkTextSecondary
                        : AppColors.textSecondary,
                  ),
                  prefixIcon: const Icon(Icons.phone_outlined,
                      color: AppColors.accent),
                  filled: true,
                  fillColor: isDark
                      ? AppColors.darkBg
                      : AppColors.background,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide(
                        color: isDark
                            ? AppColors.darkDivider
                            : AppColors.divider),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(
                        color: AppColors.accent, width: 2),
                  ),
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: Text(
                t('cancel'),
                style: TextStyle(
                  color: isDark
                      ? AppColors.darkTextSecondary
                      : AppColors.textSecondary,
                  fontSize: locale.bodySize,
                ),
              ),
            ),
            ElevatedButton(
              onPressed: () {
                _savePhone(_phoneController.text.trim());
                Navigator.pop(ctx);
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    backgroundColor: AppColors.safe,
                    behavior: SnackBarBehavior.floating,
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12)),
                    margin: const EdgeInsets.all(16),
                    content: Text(
                      t('saved'),
                      style: TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: locale.bodySize,
                      ),
                    ),
                  ),
                );
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10)),
              ),
              child: Text(
                t('save'),
                style: TextStyle(
                  color: Colors.white,
                  fontSize: locale.bodySize,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _phoneController.dispose();
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
                  t('settings'),
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: locale.headingSize,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  // ── PROTECTION ──
                  _SectionLabel(
                      t('protection_section'), textSecondary,
                      locale.subtitleSize),
                  _SettingTile(
                    title: t('link_protection'),
                    subtitle: t('check_auto'),
                    cardColor: cardColor,
                    textPrimary: textPrimary,
                    textSecondary: textSecondary,
                    locale: locale,
                    trailing: Switch(
                      value: _protectionActive,
                      onChanged: (val) =>
                          setState(() => _protectionActive = val),
                      activeColor: AppColors.accent,
                    ),
                  ),

                  const SizedBox(height: 20),

                  // ── LANGUAGE ──
                  _SectionLabel(
                      t('language_section'), textSecondary,
                      locale.subtitleSize),
                  _SettingTile(
                    title: t('display_language'),
                    subtitle: '',
                    cardColor: cardColor,
                    textPrimary: textPrimary,
                    textSecondary: textSecondary,
                    locale: locale,
                    trailing: GestureDetector(
                      onTap: () =>
                          locale.setLang(isAr ? 'en' : 'ar'),
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 6),
                        decoration: BoxDecoration(
                          color: bgColor,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                              color: isDark
                                  ? AppColors.darkDivider
                                  : AppColors.divider),
                        ),
                        child: Text(
                          isAr ? 'العربية' : 'English',
                          style: TextStyle(
                            fontWeight: FontWeight.w600,
                            color: AppColors.primary,
                            fontSize: locale.bodySize,
                          ),
                        ),
                      ),
                    ),
                  ),

                  const SizedBox(height: 20),

                  // ── APPEARANCE ──
                  _SectionLabel(
                      t('appearance_section'), textSecondary,
                      locale.subtitleSize),
                  _SettingTile(
                    title: t('large_text'),
                    subtitle: t('large_text_sub'),
                    cardColor: cardColor,
                    textPrimary: textPrimary,
                    textSecondary: textSecondary,
                    locale: locale,
                    trailing: Switch(
                      value: locale.largeText,
                      onChanged: locale.setLargeText,
                      activeColor: AppColors.accent,
                    ),
                  ),
                  const SizedBox(height: 8),
                  _SettingTile(
                    title: t('dark_mode'),
                    subtitle: t('dark_mode_sub'),
                    cardColor: cardColor,
                    textPrimary: textPrimary,
                    textSecondary: textSecondary,
                    locale: locale,
                    trailing: Switch(
                      value: locale.darkMode,
                      onChanged: locale.setDarkMode,
                      activeColor: AppColors.accent,
                    ),
                  ),

                  const SizedBox(height: 20),

                  // ── TRUSTED CONTACT ──
                  _SectionLabel(
                      t('trusted_section'), textSecondary,
                      locale.subtitleSize),
                  _SettingTile(
                    title: t('family_number'),
                    subtitle: _savedPhone.isEmpty
                        ? t('not_set')
                        : _savedPhone,
                    cardColor: cardColor,
                    textPrimary: textPrimary,
                    textSecondary: textSecondary,
                    locale: locale,
                    onTap: () => _showPhoneDialog(context, locale),
                    trailing: const Icon(
                      Icons.chevron_right,
                      color: AppColors.textSecondary,
                    ),
                  ),
                  const SizedBox(height: 8),
                  _SettingTile(
                    title: t('notify_family'),
                    subtitle: t('notify_family_sub'),
                    cardColor: cardColor,
                    textPrimary: textPrimary,
                    textSecondary: textSecondary,
                    locale: locale,
                    trailing: Switch(
                      value: locale.notifyFamily,
                      onChanged: locale.setNotifyFamily,
                      activeColor: AppColors.accent,
                    ),
                  ),

                  const SizedBox(height: 30),

                  Center(
                    child: Text(
                      t('version'),
                      style: TextStyle(
                        color: textSecondary.withOpacity(0.5),
                        fontSize: locale.subtitleSize,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const BottomNav(currentIndex: 4),
          ],
        ),
      ),
    );
  }
}

class _SectionLabel extends StatelessWidget {
  final String label;
  final Color color;
  final double fontSize;
  const _SectionLabel(this.label, this.color, this.fontSize);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8, left: 4, right: 4),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: fontSize - 1,
          fontWeight: FontWeight.w600,
          letterSpacing: 0.8,
        ),
      ),
    );
  }
}

class _SettingTile extends StatelessWidget {
  final String title;
  final String subtitle;
  final Widget trailing;
  final AppLocale locale;
  final Color cardColor;
  final Color textPrimary;
  final Color textSecondary;
  final VoidCallback? onTap;

  const _SettingTile({
    required this.title,
    required this.subtitle,
    required this.trailing,
    required this.locale,
    required this.cardColor,
    required this.textPrimary,
    required this.textSecondary,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 2),
        padding: const EdgeInsets.symmetric(
            horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: cardColor,
          borderRadius: BorderRadius.circular(14),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.04),
              blurRadius: 6,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: TextStyle(
                      fontWeight: FontWeight.w600,
                      fontSize: locale.bodySize,
                      color: textPrimary,
                    ),
                  ),
                  if (subtitle.isNotEmpty) ...[
                    const SizedBox(height: 2),
                    Text(
                      subtitle,
                      style: TextStyle(
                        color: textSecondary,
                        fontSize: locale.subtitleSize,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            trailing,
          ],
        ),
      ),
    );
  }
}