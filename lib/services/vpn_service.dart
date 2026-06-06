import 'package:flutter/services.dart';

class VpnChannel {
  static const _channel = MethodChannel('linkguard/vpn');

  static Future<void> startVpn() async {
    await _channel.invokeMethod('startVpn');
  }

  static Future<void> stopVpn() async {
    await _channel.invokeMethod('stopVpn');
  }

  static void listenForLinks(
    Function(String url) onLinkDetected, {
    Function(String url, double score)? onDangerDetected,
  }) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'onLinkDetected') {
        final domain = call.arguments as String;
        final url = 'https://$domain';
        onLinkDetected(url);
      }
      if (call.method == 'onUrlDetected') {
        final url = call.arguments as String;
        onLinkDetected(url);
      }
      if (call.method == 'showDangerScreen') {
        final args = call.arguments as Map;
        final url = args['url'] as String;
        final score = (args['score'] as num).toDouble();
        onDangerDetected?.call(url, score);
      }
    });
  }
}