import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AppLocale extends ChangeNotifier {
  String _lang = 'en';
  bool _largeText = false;
  bool _darkMode = false;
  bool _notifyFamily = false;

  String get lang => _lang;
  bool get largeText => _largeText;
  bool get darkMode => _darkMode;
  bool get notifyFamily => _notifyFamily;
  bool get isArabic => _lang == 'ar';

  double get bodySize => _largeText ? 18 : 15;
  double get titleSize => _largeText ? 24 : 20;
  double get subtitleSize => _largeText ? 16 : 13;
  double get headingSize => _largeText ? 30 : 26;
  double get buttonSize => _largeText ? 20 : 17;

  AppLocale() {
    _loadPrefs();
  }

  Future<void> _loadPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    _lang = prefs.getString('lang') ?? 'en';
    _largeText = prefs.getBool('largeText') ?? false;
    _darkMode = prefs.getBool('darkMode') ?? false;
    _notifyFamily = prefs.getBool('notifyFamily') ?? false;
    notifyListeners();
  }

  Future<void> setLang(String lang) async {
    _lang = lang;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('lang', lang);
    notifyListeners();
  }

  Future<void> setLargeText(bool val) async {
    _largeText = val;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('largeText', val);
    notifyListeners();
  }

  Future<void> setDarkMode(bool val) async {
    _darkMode = val;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('darkMode', val);
    notifyListeners();
  }

  Future<void> setNotifyFamily(bool val) async {
    _notifyFamily = val;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('notifyFamily', val);
    notifyListeners();
  }
}