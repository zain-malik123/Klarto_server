import 'package:dotenv/dotenv.dart' as dotenv;

class Config {
	static void load() {
		dotenv.load();
	}

	static String get host => dotenv.env['HOST'] ?? '0.0.0.0';
	static int get port => int.tryParse(dotenv.env['PORT'] ?? '') ?? 3000;

	static String get clientBaseUrl => dotenv.env['CLIENT_BASE_URL'] ?? dotenv.env['CLIENT_BASE_URL'] ?? 'http://localhost:3000';

	// JWT
	static String get jwtSecret => dotenv.env['JWT_SECRET'] ?? 'change-me';

	// Maileroo (legacy)
	static String get mailerooApiKey => dotenv.env['MAILEROO_API_KEY'] ?? '';
	static String get mailerooSenderAddress => dotenv.env['MAILEROO_SENDER_ADDRESS'] ?? '';

	// SMTP settings for support@klarto.io
	static String get smtpHost => dotenv.env['SUPPORT_EMAIL_SMTP_HOST'] ?? 'smtp.gmail.com';
	static int get smtpPort => int.tryParse(dotenv.env['SUPPORT_EMAIL_SMTP_PORT'] ?? '') ?? 587;
	static String get smtpUser => dotenv.env['SUPPORT_EMAIL_SMTP_USER'] ?? 'support@klarto.io';
	static String? get smtpPassword => dotenv.env['SUPPORT_EMAIL_SMTP_PASSWORD'];
}
