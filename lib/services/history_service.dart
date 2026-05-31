import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/link_entry.dart';

class HistoryService {
  static const _key = 'link_history';

  static Future<List<LinkEntry>> getHistory() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? [];
    return raw
        .map((e) => LinkEntry.fromJson(jsonDecode(e)))
        .toList()
        .reversed
        .toList();
  }

  static Future<void> addEntry(LinkEntry entry) async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? [];
    raw.add(jsonEncode(entry.toJson()));
    if (raw.length > 50) raw.removeAt(0);
    await prefs.setStringList(_key, raw);
  }

  static Future<void> deleteEntry(LinkEntry entry) async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? [];
    raw.removeWhere((e) {
      final d = jsonDecode(e);
      return d['domain'] == entry.domain &&
          d['time'] == entry.time.toIso8601String();
    });
    await prefs.setStringList(_key, raw);
  }

  static Future<void> deleteEntries(List<LinkEntry> entries) async {
    for (final e in entries) {
      await deleteEntry(e);
    }
  }

  static Future<void> clearAll() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }

  static Future<Map<String, int>> getStats() async {
    final list = await getHistory();
    int safe = 0, threats = 0;
    for (final e in list) {
      if (e.verdict == 'SAFE') {
        safe++;
      } else {
        threats++;
      }
    }
    return {'safe': safe, 'threats': threats};
  }

  static Future<List<Map<String, dynamic>>> getWeeklyStats() async {
    final list = await getHistory();
    final now = DateTime.now();
    final result = <Map<String, dynamic>>[];
    for (int i = 6; i >= 0; i--) {
      final day = DateTime(now.year, now.month, now.day - i);
      final dayEntries = list.where((e) =>
          e.time.year == day.year &&
          e.time.month == day.month &&
          e.time.day == day.day);
      result.add({
        'day': day,
        'safe': dayEntries.where((e) => e.verdict == 'SAFE').length,
        'danger': dayEntries
            .where((e) => e.verdict == 'DANGER' || e.verdict == 'WARN')
            .length,
      });
    }
    return result;
  }

  static Future<List<MapEntry<String, int>>> getTopBlocked() async {
    final list = await getHistory();
    final map = <String, int>{};
    for (final e in list) {
      if (e.verdict != 'SAFE') {
        map[e.domain] = (map[e.domain] ?? 0) + 1;
      }
    }
    final sorted = map.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    return sorted.take(5).toList();
  }

  static Future<String> exportCsv() async {
    final list = await getHistory();
    final buffer = StringBuffer();
    buffer.writeln('Domain,Verdict,Date,Time');
    for (final e in list) {
      final date =
          '${e.time.year}-${e.time.month.toString().padLeft(2, '0')}-${e.time.day.toString().padLeft(2, '0')}';
      final time =
          '${e.time.hour.toString().padLeft(2, '0')}:${e.time.minute.toString().padLeft(2, '0')}';
      buffer.writeln('${e.domain},${e.verdict},$date,$time');
    }
    return buffer.toString();
  }
}