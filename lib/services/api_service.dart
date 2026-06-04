import 'dart:convert';
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
          .timeout(const Duration(seconds: 30)); // increased for Render cold start

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final verdictStr = data['verdict']?.toString().toUpperCase() ?? 'DANGER';

        Verdict verdict;
        if (verdictStr == 'DANGER') {
          verdict = Verdict.danger;
        } else {
          verdict = Verdict.safe;
        }

        return LinkResult(
          verdict: verdict,
          url: url,
          threatScore: (data['score'] ?? 0.0).toDouble(),
          messageEn: data['message_en'] ?? 'Link analyzed.',
          messageAr: data['message_ar'] ?? 'تم تحليل الرابط.',
        );
      }
    } catch (e) {
      print('API error: $e');
    }

    // Fallback — DANGER when API unreachable (fail safe)
    return LinkResult(
      verdict: Verdict.unreachable,
      url: url,
      threatScore: 0.0,
      messageEn: 'Could not verify link. Treat with caution.',
      messageAr: 'تعذّر التحقق من الرابط. كن حذراً.',
    );
  }
}