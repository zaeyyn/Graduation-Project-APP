import 'package:shared_preferences/shared_preferences.dart';

class TrustedContactsService {
  static const _key = 'trusted_contacts';

  static Future<List<String>> getContacts() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getStringList(_key) ?? [];
  }

  static Future<void> addContact(String phone) async {
    phone = phone.trim();
    if (phone.isEmpty) return;
    final prefs = await SharedPreferences.getInstance();
    final list = prefs.getStringList(_key) ?? [];
    if (!list.contains(phone)) {
      list.add(phone);
      await prefs.setStringList(_key, list);
    }
  }

  static Future<void> removeContact(String phone) async {
    final prefs = await SharedPreferences.getInstance();
    final list = prefs.getStringList(_key) ?? [];
    list.remove(phone);
    await prefs.setStringList(_key, list);
  }
}
