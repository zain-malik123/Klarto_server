import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:mailer/mailer.dart';
import 'package:mailer/smtp_server.dart';
import 'package:klarto_server/config.dart';

class EmailService {
  /// Send an email using SMTP. Throws if SMTP password not configured.
  static Future<void> sendSupportEmail({
    required String to,
    required String subject,
    required String body,
  }) async {
    final username = Config.smtpUser;
    final password = Config.smtpPassword ?? Platform.environment['SUPPORT_EMAIL_APP_PASSWORD'];

    if (password == null || password.isEmpty) {
      throw Exception('SMTP password not configured. Set SUPPORT_EMAIL_SMTP_PASSWORD or SUPPORT_EMAIL_APP_PASSWORD environment variable.');
    }

    final smtpServer = SmtpServer(
      Config.smtpHost,
      port: Config.smtpPort,
      username: username,
      password: password,
      // Use STARTTLS for port 587
      ssl: Config.smtpPort == 465,
      ignoreBadCertificate: false,
    );

    final message = Message()
      ..from = Address(username, 'Klarto Support')
      ..recipients.add(to)
      ..subject = subject
      ..text = body;

    try {
      final sendReport = await send(message, smtpServer);
      print('Email sent: $sendReport');
    } on MailerException catch (e) {
      print('Failed to send email: $e');
      rethrow;
    }
  }

  /// Send an HTML email. Prefer Maileroo API if configured; otherwise use SMTP.
  static Future<void> sendHtmlEmail({
    required String to,
    required String subject,
    required String html,
    String fromName = 'Klarto Support',
    String? fromAddress,
  }) async {
    // If Maileroo API key + sender configured, use Maileroo for HTML emails.
    final mailerooKey = Config.mailerooApiKey;
    if (mailerooKey.isNotEmpty && Config.mailerooSenderAddress.isNotEmpty) {
      final mailerooUrl = Uri.parse('https://smtp.maileroo.com/api/v2/emails');
      final headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $mailerooKey',
      };
      final body = json.encode({
        'from': {'address': Config.mailerooSenderAddress, 'display_name': fromName},
        'to': [{'address': to, 'display_name': ''}],
        'subject': subject,
        'html': html,
      });

      final resp = await http.post(mailerooUrl, headers: headers, body: body);
      if (resp.statusCode < 200 || resp.statusCode >= 300) {
        throw Exception('Maileroo send failed: ${resp.statusCode} ${resp.body}');
      }
      return;
    }

    // Fallback to SMTP using configured support account
    final username = Config.smtpUser;
    final password = Config.smtpPassword ?? Platform.environment['SUPPORT_EMAIL_APP_PASSWORD'];
    if (password == null || password.isEmpty) {
      throw Exception('SMTP password not configured. Set SUPPORT_EMAIL_SMTP_PASSWORD or SUPPORT_EMAIL_APP_PASSWORD environment variable.');
    }

    final smtpServer = SmtpServer(
      Config.smtpHost,
      port: Config.smtpPort,
      username: username,
      password: password,
      ssl: Config.smtpPort == 465,
      ignoreBadCertificate: false,
    );

    final message = Message()
      ..from = Address(fromAddress ?? username, fromName)
      ..recipients.add(to)
      ..subject = subject
      ..html = html;

    try {
      final sendReport = await send(message, smtpServer);
      print('Email sent via SMTP: $sendReport');
    } on MailerException catch (e) {
      print('Failed to send email via SMTP: $e');
      rethrow;
    }
  }
}
