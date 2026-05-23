import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

class PhishingApiService {
  static const String apiUrl = 'https://linkguard-api-yy7v.onrender.com';
  // For Android emulator testing use: 'http://10.0.2.2:5000/check'

  static Future<Map<String, dynamic>?> checkUrl(String url) async {
    try {
      final response = await http
          .post(
            Uri.parse(apiUrl),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'url': url}),
          )
          .timeout(const Duration(seconds: 15));

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

class ScannerScreen extends StatefulWidget {
  @override
  _ScannerScreenState createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  final TextEditingController _urlController = TextEditingController();

  bool _isLoading = false;
  String _verdict = "Awaiting input...";
  double _score = 0.0;
  String _messageEn = "";
  String _messageAr = "";

  void _scanUrl() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) return;

    setState(() => _isLoading = true);

    final result = await PhishingApiService.checkUrl(url);

    if (!mounted) return;

    setState(() {
      _isLoading = false;
      if (result != null) {
        _score     = (result['score'] as num).toDouble(); // safe cast
        _verdict   = result['verdict'];
        _messageEn = result['message_en'];
        _messageAr = result['message_ar'];
      } else {
        _verdict = "Error connecting to API";
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Phishing Scanner')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            TextField(
              controller: _urlController,
              decoration: InputDecoration(labelText: 'Enter URL'),
            ),
            SizedBox(height: 12),
            ElevatedButton(
              onPressed: _isLoading ? null : _scanUrl,
              child: _isLoading
                  ? SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Text('Scan URL'),
            ),
            SizedBox(height: 20),
            Text('Verdict: $_verdict',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
            Text('Confidence Score: $_score%'),
            if (_messageEn.isNotEmpty) ...[
              SizedBox(height: 10),
              Text(_messageEn, style: TextStyle(color: Colors.grey[700])),
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

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }
}
