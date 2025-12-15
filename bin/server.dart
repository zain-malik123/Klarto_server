import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';
import 'package:postgres/postgres.dart';
import 'package:bcrypt/bcrypt.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:klarto_server/config.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
const _corsHeaders = {
  'Access-Control-Allow-Origin': '*', // Allows any origin
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Origin, Content-Type',
};

// Middleware to handle CORS.
Middleware _corsMiddleware() {
  return (Handler innerHandler) {
    return (Request request) async {
      // Handle preflight OPTIONS requests.
      if (request.method == 'OPTIONS') {
        return Response.ok(null, headers: _corsHeaders);
      }
      // Add CORS headers to the response for other requests.
      final response = await innerHandler(request);
      return response.change(headers: _corsHeaders);
    };
  };
}

// Middleware to verify JWT and add user context.
Middleware _authMiddleware() {
  return (Handler innerHandler) {
    return (Request request) async {
      final authHeader = request.headers['authorization'];
      String? token;

      if (authHeader != null && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }

      if (token == null) {
        return Response.unauthorized('Not authorized. No token found.');
      }

      try {
        final jwt = JWT.verify(token, SecretKey(Config.jwtSecret));
        final userId = jwt.payload['id'] as String;
        // Attach the user ID to the request context for later use.
        final updatedRequest = request.change(context: {'userId': userId});
        return await innerHandler(updatedRequest);
      } on JWTExpiredException {
        return Response.unauthorized('Not authorized. Token has expired.');
      } on JWTException catch (err) {
        return Response.unauthorized('Not authorized. Invalid token: ${err.message}');
      }
    };
  };
}

// A global variable for the database connection.
late final PostgreSQLConnection _db;

// Router for public endpoints that do not require authentication.
final _publicRouter = Router()
  ..post('/auth/signup', _signupHandler)
  ..get('/auth/verify', _verifyHandler)
  ..post('/auth/login', _loginHandler)
  ..post('/auth/request-password-reset', _requestPasswordResetHandler)
  ..post('/auth/reset-password', _resetPasswordHandler);

// Router for private endpoints that require a valid JWT.
final _privateRouter = Router()
  ..post('/api/filters', _createFilterHandler)
  ..get('/api/filters', _getFiltersHandler);




// Handler for the signup request.
Future<Response> _signupHandler(Request request) async {
  try {
    // 1. Read and parse the request body from the Flutter app.
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final name = body['name'] as String?;
    final email = body['email'] as String?;
    final password = body['password'] as String?;

    // 2. Validate the incoming data.
    if (name == null || email == null || password == null || name.isEmpty || email.isEmpty || password.length < 8) {
      return Response(
        400, // Bad Request
        body: json.encode({'message': 'Name, email, and a password of at least 8 characters are required.'}),
        headers: {'Content-Type': 'application/json'},
      );
    }

    // 3. Hash the password for security. NEVER store plain text passwords.
    final hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

    // 4. Generate a secure, random verification token.
    final tokenBytes = List<int>.generate(32, (_) => Random.secure().nextInt(256));
    final verificationToken = base64Url.encode(tokenBytes);
    final tokenExpiry = DateTime.now().add(const Duration(hours: 1));

    // 5. Insert the new user into the database with the token.
    await _db.query(
      r'''
      INSERT INTO users (name, email, password_hash, verification_token, verification_token_expires_at) 
      VALUES (@name, @email, @passwordHash, @token, @tokenExpiry)
      ''',
      substitutionValues: {
        'name': name,
        'email': email,
        'passwordHash': hashedPassword,
        'token': verificationToken,
        'tokenExpiry': tokenExpiry.toIso8601String(),
      },
    );

    // 6. Send the verification email via Maileroo HTTP API.
    final verificationUrl = '${Config.clientBaseUrl}/verify-email?token=$verificationToken';
    final emailHtmlBody = '''
        <h1>Welcome to Klarto, $name!</h1>
        <p>Thank you for signing up. Please click the link below to verify your email address:</p>
        <p><a href="$verificationUrl">Verify My Email</a></p>
        <p>This link will expire in 1 hour.</p>
      ''';

    final mailerooUrl = Uri.parse('https://smtp.maileroo.com/api/v2/emails');
    final mailerooHeaders = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ${Config.mailerooApiKey}',
    };
    final mailerooBody = json.encode({
      'from': {'address': Config.mailerooSenderAddress, 'display_name': 'Klarto Team'},
      'to': [{'address': email, 'display_name': name}],
      'subject': 'Welcome to Klarto! Please Verify Your Email',
      'html': emailHtmlBody,
    });
    
    try {
      final response = await http.post(mailerooUrl, headers: mailerooHeaders, body: mailerooBody);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        print('Maileroo API Error: ${response.statusCode} - ${response.body}');
      }
    } catch (e) {
      print('Error sending email: $e');
    }

    // 7. Return a success response.
    return Response(
      201, // Created
      body: json.encode({'message': 'Signup successful! Please check your email to verify your account.'}),
      headers: {'Content-Type': 'application/json'},
    );

  } on PostgreSQLException catch (e, stackTrace) {
    // Log the detailed database error
    print('Database error occurred: $e');
    print(stackTrace);
    // Handle specific database errors. The most common one is a duplicate email.
    if (e.code == '23505') { // Unique violation
      return Response(
        409, // Conflict
        body: json.encode({'message': 'A user with this email already exists.'}),
        headers: {'Content-Type': 'application/json'},
      );
    }
    // For other database errors, return a generic server error.
    return Response.internalServerError(body: 'Database error: ${e.message}');
  } catch (e, stackTrace) {
    // Handle any other unexpected errors.
    print('An unexpected error occurred: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for the login request.
Future<Response> _loginHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final email = body['email'] as String?;
    final password = body['password'] as String?;

    if (email == null || password == null || email.isEmpty || password.isEmpty) {
      return Response(400, body: json.encode({'message': 'Email and password are required.'}));
    }

    // 1. Find the user by email.
    final result = await _db.query(
      'SELECT id, password_hash, is_verified FROM users WHERE email = @email',
      substitutionValues: {'email': email},
    );

    if (result.isEmpty) {
      return Response(401, body: json.encode({'message': 'Invalid email or password.'}));
    }

    final user = result.first;
    final userId = user[0] as String;
    final storedHash = user[1] as String;
    final isVerified = user[2] as bool;

    // 2. Check if the account is verified.
    if (!isVerified) {
      return Response(403, body: json.encode({'message': 'Please verify your email before logging in.'}));
    }

    // 3. Verify the password.
    if (!BCrypt.checkpw(password, storedHash)) {
      return Response(401, body: json.encode({'message': 'Invalid email or password.'}));
    }

    // 4. Generate a JWT.
    final jwt = JWT({'id': userId});
    final token = jwt.sign(SecretKey(Config.jwtSecret), expiresIn: const Duration(days: 7));

    return Response.ok(
      json.encode({'token': token}),
      headers: {'Content-Type': 'application/json'},
    );

  } catch (e, stackTrace) {
    print('Error during login: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for the password reset request.
Future<Response> _requestPasswordResetHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    final email = body['email'] as String?;

    if (email == null || email.isEmpty) {
      return Response(400, body: json.encode({'message': 'Email is required.'}));
    }

    // 1. Find user by email.
    final result = await _db.query(
      'SELECT id, name FROM users WHERE email = @email',
      substitutionValues: {'email': email},
    );

    // SECURITY NOTE: To prevent email enumeration attacks, we always return a
    // success response, even if the email is not found.
    if (result.isNotEmpty) {
      final user = result.first;
      final userId = user[0] as String;
      final name = user[1] as String;

      // 2. Generate and store a password reset token.
      final tokenBytes = List<int>.generate(32, (_) => Random.secure().nextInt(256));
      final resetToken = base64Url.encode(tokenBytes);
      final tokenExpiry = DateTime.now().add(const Duration(hours: 1));

      await _db.query(
        'UPDATE users SET password_reset_token = @token, password_reset_token_expires_at = @expiry WHERE id = @id',
        substitutionValues: {
          'token': resetToken,
          'expiry': tokenExpiry.toIso8601String(),
          'id': userId,
        },
      );

      // 3. Send the password reset email.
      final resetUrl = '${Config.clientBaseUrl}/reset-password-confirm?token=$resetToken';
      final emailHtmlBody = '''
          <h1>Klarto Password Reset</h1>
          <p>Hello $name,</p>
          <p>We received a request to reset your password. Click the link below to set a new one:</p>
          <p><a href="$resetUrl">Reset My Password</a></p>
          <p>This link will expire in 1 hour. If you did not request this, you can safely ignore this email.</p>
        ''';
      
      // Re-using the same email sending logic.
      // In a larger app, this would be extracted into a dedicated EmailService.
      final mailerooUrl = Uri.parse('https://smtp.maileroo.com/api/v2/emails');
      final mailerooHeaders = {'Content-Type': 'application/json', 'Authorization': 'Bearer ${Config.mailerooApiKey}'};
      final mailerooBody = json.encode({'from': {'address': Config.mailerooSenderAddress, 'display_name': 'Klarto Support'},'to': [{'address': email, 'display_name': name}],'subject': 'Your Klarto Password Reset Request','html': emailHtmlBody});
      // Only send the email if a user was found.
      http.post(mailerooUrl, headers: mailerooHeaders, body: mailerooBody).catchError((e) => print('Failed to send password reset email: $e'));
    }

    // Always return success.
    return Response.ok(json.encode({'message': 'If an account with that email exists, a password reset link has been sent.'}));

  } catch (e, stackTrace) {
    print('Error during password reset request: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler to set the new password.
Future<Response> _resetPasswordHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    final token = body['token'] as String?;
    final newPassword = body['newPassword'] as String?;

    if (token == null || newPassword == null || token.isEmpty || newPassword.length < 8) {
      return Response(400, body: json.encode({'message': 'A valid token and a new password of at least 8 characters are required.'}));
    }

    // 1. Find user by the reset token.
    final result = await _db.query(
      'SELECT id, password_reset_token_expires_at FROM users WHERE password_reset_token = @token',
      substitutionValues: {'token': token},
    );

    if (result.isEmpty) {
      return Response(400, body: json.encode({'message': 'Invalid or expired reset token.'}));
    }

    final user = result.first;
    final userId = user[0] as String;
    final expiresAt = user[1] as DateTime;

    // 2. Check if the token has expired.
    if (expiresAt.isBefore(DateTime.now())) {
      return Response(400, body: json.encode({'message': 'Invalid or expired reset token.'}));
    }

    // 3. Hash the new password.
    final hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt());

    // 4. Update the password and clear the reset token fields.
    await _db.query(
      '''
      UPDATE users 
      SET password_hash = @passwordHash, 
          password_reset_token = NULL, 
          password_reset_token_expires_at = NULL 
      WHERE id = @id
      ''',
      substitutionValues: {'passwordHash': hashedPassword, 'id': userId},
    );

    return Response.ok(json.encode({'message': 'Your password has been reset successfully.'}));

  } catch (e, stackTrace) {
    print('Error during password reset confirmation: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for getting all filters for a user.
Future<Response> _getFiltersHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }

    final result = await _db.query(
      'SELECT id, name, query, color, is_favorite, created_at, description FROM filters WHERE user_id = @userId ORDER BY created_at DESC',
      substitutionValues: {'userId': userId},
    );

    final filters = result.map((row) => row.toColumnMap()).toList();

    return Response.ok(json.encode(filters), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error getting filters: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for creating a new filter.
Future<Response> _createFilterHandler(Request request) async {
  try {
    // The user ID is retrieved from the context set by the auth middleware.
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final name = body['name'] as String?;
    final query = body['query'] as String?;
    final color = body['color'] as String?;
    final description = body['description'] as String?; // Can be null
    final isFavorite = body['is_favorite'] as bool?;

    if (name == null || query == null || color == null || isFavorite == null) {
      return Response(400, body: json.encode({'message': 'Name, query, color, and is_favorite are required.'}));
    }

    final result = await _db.query(
      r'''
      INSERT INTO filters (user_id, name, query, color, is_favorite, description)
      VALUES (@userId, @name, @query, @color, @isFavorite, @description)
      RETURNING id, name, query, color, is_favorite, created_at, description
      ''',
      substitutionValues: {
        'userId': userId,
        'name': name,
        'query': query,
        'color': color,
        'isFavorite': isFavorite,
        'description': description,
      },
    );

    final newFilter = result.first.toColumnMap();
    return Response(201, body: json.encode(newFilter), headers: {'Content-Type': 'application/json'});

  } catch (e, stackTrace) {
    print('Error creating filter: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for the email verification request.
Future<Response> _verifyHandler(Request request) async {  
  final token = request.url.queryParameters['token'];

  if (token == null || token.isEmpty) {
    return _generateHtmlResponse(
      title: 'Verification Failed',
      message: 'No verification token was provided. Please try signing up again.',
      isSuccess: false,
    );
  }

  try {
    // Find user by token
    final result = await _db.query(
      'SELECT id, verification_token_expires_at FROM users WHERE verification_token = @token',
      substitutionValues: {'token': token},
    );

    if (result.isEmpty) {
      return _generateHtmlResponse(
        title: 'Invalid Token',
        message: 'This verification link is not valid. It may have already been used.',
        isSuccess: false,
      );
    }

    final user = result.first;
    final userId = user[0] as String;
    final expiresAt = user[1] as DateTime;

    // Check if token is expired
    if (expiresAt.isBefore(DateTime.now())) {
      return _generateHtmlResponse(
        title: 'Link Expired',
        message: 'This verification link has expired. Please request a new one.',
        isSuccess: false,
      );
    }

    // Update user to be verified
    await _db.query(
      'UPDATE users SET is_verified = true, verification_token = NULL, verification_token_expires_at = NULL WHERE id = @id',
      substitutionValues: {'id': userId},
    );

    return _generateHtmlResponse(
      title: 'Email Verified Successfully!',
      message: 'Thank you for verifying your email. You can now log in to your account.',
      isSuccess: true,
    );
  } catch (e, stackTrace) {
    print('Error during verification: $e');
    print(stackTrace);
    return _generateHtmlResponse(
      title: 'Server Error',
      message: 'An unexpected error occurred. Please try again later.',
      isSuccess: false,
    );
  }
}

// Helper to generate a user-friendly HTML response page.
Response _generateHtmlResponse({required String title, required String message, required bool isSuccess}) {
  final icon = isSuccess ? '✅' : '❌';
  final color = isSuccess ? '#28a745' : '#dc3545';

  final html = '''
    <!DOCTYPE html><html><head><title>Klarto Verification</title><style>body{font-family:sans-serif;display:grid;place-items:center;height:100vh;margin:0;background-color:#f8f9fa;}.card{background:white;padding:40px;border-radius:12px;box-shadow:0 4px 16px rgba(0,0,0,0.1);text-align:center;max-width:400px;}.icon{font-size:48px;}.title{font-size:24px;font-weight:600;color:#383838;margin:16px 0 8px;}.message{color:#707070;line-height:1.5;}.button{display:inline-block;background-color:#3D4CD6;color:white;padding:12px 24px;margin-top:24px;border-radius:8px;text-decoration:none;font-weight:500;}</style></head><body><div class="card"><div class="icon" style="color:$color;">$icon</div><h1 class="title">$title</h1><p class="message">$message</p><a href="${Config.clientBaseUrl}" class="button">Back to Login</a></div></body></html>
  ''';

  return Response.ok(html, headers: {'Content-Type': 'text/html'});
}

void main(List<String> args) async {
  // --- Database Connection ---
  _db = PostgreSQLConnection(
    Config.dbHost,
    Config.dbPort,
    Config.dbName,
    username: Config.dbUser,
    password: Config.dbPassword,
  );

  await _db.open();
  print('Successfully connected to the database.');

  // --- Server Setup ---
  // Combine public and private routes. Apply auth middleware only to private routes.
  final cascade = Cascade().add(_publicRouter).add(_authMiddleware()(_privateRouter));

  final handler = const Pipeline()
      .addMiddleware(logRequests()) // Log all incoming requests.
      .addMiddleware(_corsMiddleware()) // Add our new CORS middleware.
      .addHandler(cascade.handler);

  final server = await io.serve(handler, Config.host, Config.port);

  print('Server listening at http://${server.address.host}:${server.port}');
}