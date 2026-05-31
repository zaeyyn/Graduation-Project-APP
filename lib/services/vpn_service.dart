import 'package:flutter/services.dart';

class VpnChannel {
  static const _channel = MethodChannel('linkguard/vpn');

  // شغّل الـ VPN
  static Future<void> startVpn() async {
    await _channel.invokeMethod('startVpn');
  }

  // وقّف الـ VPN
  static Future<void> stopVpn() async {
    await _channel.invokeMethod('stopVpn');
  }

  // استقبل الروابط من الـ VPN
  // onLinkDetected: function بتشتغل كل ما يجي رابط جديد
  static void listenForLinks(Function(String url) onLinkDetected) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'onLinkDetected') {
        final domain = call.arguments as String;
        // حوّل الـ domain لـ URL كامل
        final url = 'https://$domain';
        onLinkDetected(url);
      }
    });
  }
}