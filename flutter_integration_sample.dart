import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

class PhishingApiService {
  // Replace with your production URL or use 10.0.2.2 for Android Emulator connecting to localhost
  static const String apiUrl = 'http://127.0.0.1:5000/check';

  /// Sends a URL to the Python Flask API to determine its safety.
  /// [mode] can be "balanced" or "protective"
  static Future<Map<String, dynamic>?> checkUrl(String url, {String mode = 'balanced'}) async {
    try {
      final response = await http.post(
        Uri.parse(apiUrl),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'url': url,
          'mode': mode,
        }),
      );

      if (response.statusCode == 200) {
        return jsonDecode(response.body); // Contains 'probability', 'active_verdict', etc.
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

// Example usage in a Stateful Widget
class ScannerScreen extends StatefulWidget {
  @override
  _ScannerScreenState createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  final TextEditingController _urlController = TextEditingController();
  String _verdict = "Awaiting input...";
  double _score = 0.0;
  String _messageEn = "";
  String _messageAr = "";
  bool _isProtectiveMode = false;

  void _scanUrl() async {
    final url = _urlController.text;
    final mode = _isProtectiveMode ? 'protective' : 'balanced';

    final result = await PhishingApiService.checkUrl(url, mode: mode);
    
    if (result != null) {
      setState(() {
        _score = result['score'];
        _verdict = result['verdict'];
        _messageEn = result['message_en'];
        _messageAr = result['message_ar'];
      });
    } else {
      setState(() {
        _verdict = "Error connecting to API";
      });
    }
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
            SwitchListTile(
              title: Text("Extra Protective Mode"),
              value: _isProtectiveMode,
              onChanged: (bool value) {
                setState(() => _isProtectiveMode = value);
              },
            ),
            ElevatedButton(
              onPressed: _scanUrl,
              child: Text('Scan URL'),
            ),
            SizedBox(height: 20),
            Text('Verdict: $_verdict', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
            Text('Confidence Score: $_score%'),
            if (_messageEn.isNotEmpty) ...[
              SizedBox(height: 10),
              Text(_messageEn, style: TextStyle(color: Colors.grey[700])),
              Text(_messageAr, style: TextStyle(color: Colors.grey[700], fontSize: 16)),
            ],
          ],
        ),
      ),
    );
  }
}
