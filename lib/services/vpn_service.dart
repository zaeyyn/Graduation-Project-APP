import 'package:flutter/services.dart';

class VpnChannel {
  static const _channel = MethodChannel('linkguard/vpn');

  static Future<void> startVpn() async {
    await _channel.invokeMethod('startVpn');
  }

  static Future<void> stopVpn() async {
    await _channel.invokeMethod('stopVpn');
  }

  /// Asks the native side whether the VPN is actually active right now,
  /// instead of relying on a value cached in the Flutter widget tree.
  /// Returns false (rather than throwing) if the check fails for any reason.
  static Future<bool> isVpnActive() async {
    try {
      final result = await _channel.invokeMethod('isVpnActive');
      return result as bool? ?? false;
    } catch (e) {
      return false;
    }
  }

  static void listenForLinks(
      Function(String url) onLinkDetected, {
        Function(String url, double score)? onDangerDetected,
        Function(String url, String verdict, double score)? onLinkChecked,
        Function()? onVpnDenied,
      }) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'onLinkDetected') {
        final domain = call.arguments as String;
        onLinkDetected('https://$domain');
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
      if (call.method == 'onLinkChecked') {
        final args = call.arguments as Map;
        final url = args['url'] as String;
        final verdict = args['verdict'] as String;
        final score = (args['score'] as num).toDouble();
        onLinkChecked?.call(url, verdict, score);
      }
      if (call.method == 'onVpnDenied') {
        onVpnDenied?.call();
      }
    });
  }
}