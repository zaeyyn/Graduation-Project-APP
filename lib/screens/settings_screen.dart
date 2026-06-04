import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../utils/app_texts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_locale.dart';
import '../widgets/bottom_nav.dart';
import '../services/trusted_contacts_service.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _protectionActive = true;

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
                            horizontal: 14, vertical: 7),
                        decoration: BoxDecoration(
                          color: isDark
                              ? const Color(0xFF2D3748)
                              : Colors.white,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: isDark
                                ? const Color(0xFF4A5568)
                                : AppColors.accent,
                            width: 1.5,
                          ),
                        ),
                        child: Text(
                          isAr ? 'العربية' : 'English',
                          style: TextStyle(
                            fontWeight: FontWeight.w600,
                            color: isDark
                                ? Colors.white
                                : AppColors.primary,
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

                  // ── TRUSTED CONTACTS ──
                  _SectionLabel(
                      t('trusted_section'), textSecondary,
                      locale.subtitleSize),
                  _TrustedContactsWidget(
                    locale: locale,
                    cardColor: cardColor,
                    textPrimary: textPrimary,
                    textSecondary: textSecondary,
                    isDark: isDark,
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

// ── Trusted Contacts Widget ──
class _TrustedContactsWidget extends StatefulWidget {
  final AppLocale locale;
  final Color cardColor;
  final Color textPrimary;
  final Color textSecondary;
  final bool isDark;

  const _TrustedContactsWidget({
    required this.locale,
    required this.cardColor,
    required this.textPrimary,
    required this.textSecondary,
    required this.isDark,
  });

  @override
  State<_TrustedContactsWidget> createState() =>
      _TrustedContactsWidgetState();
}

class _TrustedContactsWidgetState
    extends State<_TrustedContactsWidget> {
  List<String> _contacts = [];
  final TextEditingController _ctrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final list = await TrustedContactsService.getContacts();
    if (mounted) setState(() => _contacts = list);
  }

  Future<void> _add() async {
    final phone = _ctrl.text.trim();
    if (phone.isEmpty) return;
    await TrustedContactsService.addContact(phone);
    _ctrl.clear();
    await _load();
  }

  Future<void> _remove(String phone) async {
    await TrustedContactsService.removeContact(phone);
    await _load();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final locale = widget.locale;
    final t = (String k) => AppTexts.get(k, locale.lang);

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: widget.cardColor,
        borderRadius: BorderRadius.circular(14),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.04),
            blurRadius: 6,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            t('family_number'),
            style: TextStyle(
              fontWeight: FontWeight.w600,
              fontSize: locale.bodySize,
              color: widget.textPrimary,
            ),
          ),
          const SizedBox(height: 12),

          // Input row
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _ctrl,
                  keyboardType: TextInputType.phone,
                  textDirection: TextDirection.ltr,
                  style: TextStyle(
                    color: widget.textPrimary,
                    fontSize: locale.bodySize,
                  ),
                  decoration: InputDecoration(
                    hintText: t('trusted_hint'),
                    hintStyle: TextStyle(
                      color: widget.textSecondary,
                      fontSize: locale.subtitleSize,
                    ),
                    prefixIcon: const Icon(
                      Icons.phone_outlined,
                      color: AppColors.accent,
                      size: 20,
                    ),
                    filled: true,
                    fillColor: widget.isDark
                        ? AppColors.darkBg
                        : AppColors.background,
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: BorderSide(
                        color: widget.isDark
                            ? AppColors.darkDivider
                            : AppColors.divider,
                      ),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(
                        color: AppColors.accent,
                        width: 2,
                      ),
                    ),
                    isDense: true,
                    contentPadding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 10,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              ElevatedButton(
                onPressed: _add,
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.primary,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 12,
                  ),
                ),
                child: Text(
                  t('add_trusted'),
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: locale.subtitleSize,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),

          const SizedBox(height: 10),

          // Contacts list
          if (_contacts.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 8),
              child: Text(
                t('no_trusted'),
                style: TextStyle(
                  color: widget.textSecondary.withOpacity(0.6),
                  fontSize: locale.subtitleSize,
                  fontStyle: FontStyle.italic,
                ),
              ),
            )
          else
            ..._contacts.map(
              (phone) => Container(
                margin: const EdgeInsets.only(bottom: 8),
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 10,
                ),
                decoration: BoxDecoration(
                  color: AppColors.accent.withOpacity(0.07),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: AppColors.accent.withOpacity(0.2),
                  ),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.person_outline,
                      color: AppColors.accent,
                      size: 18,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        phone,
                        textDirection: TextDirection.ltr,
                        style: TextStyle(
                          color: widget.textPrimary,
                          fontSize: locale.bodySize,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                    GestureDetector(
                      onTap: () => _remove(phone),
                      child: const Icon(
                        Icons.close,
                        color: AppColors.danger,
                        size: 18,
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}

// ── Section Label ──
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

// ── Setting Tile ──
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
