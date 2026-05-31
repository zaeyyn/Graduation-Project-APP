import 'package:shared_preferences/shared_preferences.dart';

class WhitelistService {
  static const _key = 'whitelist';

  static Future<List<String>> getWhitelist() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getStringList(_key) ?? [];
  }

  static Future<void> addDomain(String domain) async {
    domain = domain.trim().toLowerCase().replaceAll('https://', '').replaceAll('http://', '').replaceAll('www.', '');
    if (domain.isEmpty) return;
    final prefs = await SharedPreferences.getInstance();
    final list = prefs.getStringList(_key) ?? [];
    if (!list.contains(domain)) {
      list.add(domain);
      await prefs.setStringList(_key, list);
    }
  }

  static Future<void> removeDomain(String domain) async {
    final prefs = await SharedPreferences.getInstance();
    final list = prefs.getStringList(_key) ?? [];
    list.remove(domain);
    await prefs.setStringList(_key, list);
  }

  static Future<bool> isDomainTrusted(String url) async {
    final domain = Uri.tryParse(url)?.host.replaceAll('www.', '') ?? '';
    final list = await getWhitelist();
    return list.contains(domain);
  }
}