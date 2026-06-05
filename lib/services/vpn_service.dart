import 'package:flutter/services.dart';

class VpnChannel {
  static const _channel = MethodChannel('linkguard/vpn');

  // Start the VPN
  static Future<void> startVpn() async {
    await _channel.invokeMethod('startVpn');
  }

  // Stop the VPN
  static Future<void> stopVpn() async {
    await _channel.invokeMethod('stopVpn');
  }

  // Listen for links from both VPN service AND Accessibility service
  static void listenForLinks(Function(String url) onLinkDetected) {
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
    });
  }
}