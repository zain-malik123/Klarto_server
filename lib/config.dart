import 'package:dotenv/dotenv.dart';

class Config {
  static final _env = DotEnv(includePlatformEnvironment: true)..load();

  /// Kept for compatibility with older code that calls `Config.load()`.
  static void load() {}

  static String get host => _env['HOST'] ?? '0.0.0.0';
  static int get port => int.parse(_env['PORT'] ?? '8080');

  static String get dbHost => _env['DB_HOST']!;
  static int get dbPort => int.parse(_env['DB_PORT']!);
  static String get dbName => _env['DB_NAME']!;
  static String get dbUser => _env['DB_USER']!;
  static String get dbPassword => _env['DB_PASSWORD']!;

  static String get mailerooApiKey => _env['MAILEROO_API_KEY'] ?? '';
  static String get mailerooSenderAddress => _env['MAILEROO_SENDER_ADDRESS'] ?? '';

  // SMTP settings for support@klarto.io (used by EmailService)
  static String get smtpHost => _env['SUPPORT_EMAIL_SMTP_HOST'] ?? 'smtp.gmail.com';
  static int get smtpPort => int.tryParse(_env['SUPPORT_EMAIL_SMTP_PORT'] ?? '') ?? 587;
  static String get smtpUser => _env['SUPPORT_EMAIL_SMTP_USER'] ?? 'support@klarto.io';
  static String? get smtpPassword => _env['SUPPORT_EMAIL_SMTP_PASSWORD'];

  static String get jwtSecret => _env['JWT_SECRET']!;

  static String get clientBaseUrl => _env['CLIENT_BASE_URL']!;

  static String get stripeSecretKey => _env['STRIPE_SECRET_KEY'] ?? '';

  static String get serverBaseUrl {
    // This is useful for constructing URLs within the server if needed.
    // The client-side base URL will be configured separately in the Flutter app.
    // When listening on 0.0.0.0, the connectable address for local testing is localhost.
    final connectableHost = (host == '0.0.0.0') ? 'localhost' : host;
    return 'http://$connectableHost:$port';
  }
}