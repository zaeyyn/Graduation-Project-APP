import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

enum Verdict { safe, danger, unreachable }

class LinkResult {
  final Verdict verdict;
  final String url;
  final double threatScore;
  final String messageEn;
  final String messageAr;

  LinkResult({
    required this.verdict,
    required this.url,
    required this.threatScore,
    required this.messageEn,
    required this.messageAr,
  });
}

class ApiService {
  static const String baseUrl = 'https://linkguard-api-yy7v.onrender.com';

  static Future<LinkResult> checkUrl(String url) async {
    try {
      final response = await http
          .post(
        Uri.parse('$baseUrl/check'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'url': url}),
      )
          .timeout(const Duration(seconds: 30));

      // Log the raw response so you can see exactly what the API returns
      debugPrint('API status: ${response.statusCode}');
      debugPrint('API body: ${response.body}');

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final verdictStr = data['verdict']?.toString().toUpperCase() ?? '';
        final score = (data['score'] ?? 0.0).toDouble();

        debugPrint('Parsed verdict: $verdictStr | score: $score');

        // FIXED: only treat explicitly 'SAFE' as safe — everything else is danger
        // This prevents unknown/unexpected values from silently passing as safe
        Verdict verdict;
        if (verdictStr == 'SAFE') {
          verdict = Verdict.safe;
        } else if (verdictStr == 'DANGER' ||
            verdictStr == 'UNSAFE' ||
            verdictStr == 'MALICIOUS' ||
            verdictStr == 'PHISHING' ||
            verdictStr == 'WARN' ||
            verdictStr == 'WARNING') {
          verdict = Verdict.danger;
        } else {
          // Unknown verdict — log it and treat as danger to be safe
          debugPrint('⚠️ Unknown verdict string from API: "$verdictStr"');
          verdict = Verdict.danger;
        }

        return LinkResult(
          verdict: verdict,
          url: url,
          threatScore: score,
          messageEn: data['message_en'] ?? 'Link analyzed.',
          messageAr: data['message_ar'] ?? 'تم تحليل الرابط.',
        );
      } else {
        debugPrint('API returned non-200 status: ${response.statusCode}');
      }
    } catch (e) {
      debugPrint('API error: $e');
    }

    // Fallback — treat as unreachable when API fails
    return LinkResult(
      verdict: Verdict.unreachable,
      url: url,
      threatScore: 0.0,
      messageEn: 'Could not verify link. Treat with caution.',
      messageAr: 'تعذّر التحقق من الرابط. كن حذراً.',
    );
  }
}