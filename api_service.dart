import 'dart:convert';
import 'package:http/http.dart' as http;

enum Verdict { safe, warning, danger }

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
  // غيّر هاد لما يكون السيرفر جاهز
  static const String baseUrl = 'https://your-api-server.com';

  static Future<LinkResult> checkUrl(String url) async {
    try {
      final response = await http
          .post(
            Uri.parse('$baseUrl/check'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'url': url}),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final verdictStr = data['verdict']?.toString().toUpperCase() ?? 'SAFE';

        Verdict verdict;
        if (verdictStr == 'DANGER') {
          verdict = Verdict.danger;
        } else if (verdictStr == 'WARNING') {
          verdict = Verdict.warning;
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
    } catch (_) {}

    // Fallback — Safe by default when API unreachable
    return LinkResult(
      verdict: Verdict.safe,
      url: url,
      threatScore: 0.0,
      messageEn: 'Could not verify link. Proceeding with caution.',
      messageAr: 'تعذّر التحقق من الرابط.',
    );
  }
}
