import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

class PhishingApiService {
  static const String _baseUrl = 'https://linkguard-api-yy7v.onrender.com';
  // For Android emulator testing use: 'http://10.0.2.2:5000'

  // FIXED: was pointing to base URL, missing /check endpoint
  static Future<Map<String, dynamic>?> checkUrl(String url) async {
    try {
      final response = await http
          .post(
        Uri.parse('$_baseUrl/check'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'url': url}),
      )
          .timeout(const Duration(seconds: 30));

      if (response.statusCode == 200) {
        return jsonDecode(response.body) as Map<String, dynamic>;
      } else {
        debugPrint('API Error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      debugPrint('Network Exception: $e');
      return null;
    }
  }
}

// FIXED: added super.key, const constructor, and proper widget key handling
class ScannerScreen extends StatefulWidget {
  const ScannerScreen({super.key});

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  final TextEditingController _urlController = TextEditingController();

  bool _isLoading = false;
  String _verdict = 'Awaiting input...';
  double _score = 0.0;
  String _messageEn = '';
  String _messageAr = '';

  Future<void> _scanUrl() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) return;

    setState(() => _isLoading = true);

    final result = await PhishingApiService.checkUrl(url);

    if (!mounted) return;

    setState(() {
      _isLoading = false;
      if (result != null) {
        _score     = (result['score'] as num).toDouble();
        _verdict   = result['verdict'] as String;
        _messageEn = result['message_en'] as String;
        _messageAr = result['message_ar'] as String;
      } else {
        _verdict   = 'Error connecting to API';
        _messageEn = '';
        _messageAr = '';
      }
    });
  }

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final verdictColor = _verdict == 'DANGER'
        ? Colors.red
        : _verdict == 'SAFE'
        ? Colors.green
        : Colors.grey;

    return Scaffold(
      appBar: AppBar(title: const Text('Phishing Scanner')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _urlController,
              decoration: const InputDecoration(
                labelText: 'Enter URL',
                hintText: 'https://example.com',
              ),
              keyboardType: TextInputType.url,
              autocorrect: false,
            ),
            const SizedBox(height: 12),
            ElevatedButton(
              onPressed: _isLoading ? null : _scanUrl,
              child: _isLoading
                  ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
                  : const Text('Scan URL'),
            ),
            const SizedBox(height: 20),
            Text(
              'Verdict: $_verdict',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
                color: verdictColor,
              ),
            ),
            Text('Confidence Score: $_score%'),
            if (_messageEn.isNotEmpty) ...[
              const SizedBox(height: 10),
              Text(
                _messageEn,
                style: TextStyle(color: Colors.grey[700]),
              ),
              Directionality(
                textDirection: TextDirection.rtl,
                child: Text(
                  _messageAr,
                  style: TextStyle(color: Colors.grey[700], fontSize: 16),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}