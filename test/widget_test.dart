import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:flutter_application_1/main.dart';
import 'package:flutter_application_1/widgets/app_locale.dart';

void main() {
  testWidgets('App launches without crashing', (WidgetTester tester) async {
    await tester.pumpWidget(
      ChangeNotifierProvider(
        create: (_) => AppLocale(),
        child: const LinkGuardApp(initialRoute: '/home'),
      ),
    );

    // Verify the app renders without errors
    expect(find.byType(MaterialApp), findsOneWidget);
  });
}