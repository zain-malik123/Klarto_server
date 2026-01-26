import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';
import 'package:postgres/postgres.dart';
import 'package:bcrypt/bcrypt.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:klarto_server/config.dart';
import 'package:klarto_server/email_service.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:shelf_static/shelf_static.dart';
import 'package:path/path.dart' as p;
// Removed multipart imports; upload now expects JSON with base64 data.

const _corsHeaders = {
  'Access-Control-Allow-Origin': '*', // Allows any origin
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
  'Access-Control-Allow-Headers': 'Origin, Content-Type, Authorization',
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
// Handler to return invited members for teams the user belongs to or invites they sent.
Future<Response> _getInvitedMembersHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    // Return invitations where the requester is the inviter or is a member of the team
    final rows = await _db.query(r'''
      SELECT i.id, i.team_id, i.invited_user_id, i.email, i.status, i.invite_token_expires_at, i.created_at, u.name AS invited_name, u.profile_picture_base64
      FROM invitations i
      LEFT JOIN users u ON u.id = i.invited_user_id
      WHERE i.inviter_id = @userId OR i.team_id IN (SELECT team_id FROM team_members WHERE user_id = @userId)
      ORDER BY i.created_at DESC
    ''', substitutionValues: {'userId': userId});

    final List<Map<String, dynamic>> results = rows.map((r) {
      final m = r.toColumnMap();
      if (m['created_at'] is DateTime) m['created_at'] = (m['created_at'] as DateTime).toIso8601String();
      if (m['invite_token_expires_at'] is DateTime) m['invite_token_expires_at'] = (m['invite_token_expires_at'] as DateTime).toIso8601String();
      return m;
    }).toList();

    return Response.ok(json.encode(results), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getInvitedMembersHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler to return all users (available members) — authenticated.
Future<Response> _getAllUsersHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final rows = await _db.query(r'''
      SELECT id, name, email, profile_picture_base64
      FROM users
      ORDER BY LOWER(name) ASC
    ''');

    final users = rows.map((r) {
      final m = r.toColumnMap();
      return m;
    }).toList();

    return Response.ok(json.encode(users), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getAllUsersHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler to return current team members for the user's team.
Future<Response> _getTeamMembersHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    String? teamId;
    final ownerRes = await _db.query('SELECT id FROM teams WHERE owner_id = @owner', substitutionValues: {'owner': userId});
    if (ownerRes.isNotEmpty) {
      teamId = ownerRes.first[0] as String;
    } else {
      final memberRes = await _db.query('SELECT team_id FROM team_members WHERE user_id = @user LIMIT 1', substitutionValues: {'user': userId});
      if (memberRes.isNotEmpty) teamId = memberRes.first[0] as String;
    }

    if (teamId == null) return Response.ok(json.encode([]), headers: {'Content-Type': 'application/json'});

    final rows = await _db.query(r'''
      SELECT tm.id AS membership_id, u.id AS user_id, u.name, u.email, tm.role, u.profile_picture_base64, tm.joined_at
      FROM team_members tm
      JOIN users u ON u.id = tm.user_id
      WHERE tm.team_id = @team
      ORDER BY tm.joined_at ASC
    ''', substitutionValues: {'team': teamId});

    final members = rows.map((r) {
      final m = r.toColumnMap();
      if (m['joined_at'] is DateTime) m['joined_at'] = (m['joined_at'] as DateTime).toIso8601String();
      return m;
    }).toList();

    return Response.ok(json.encode(members), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getTeamMembersHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler to add an existing user to the requester's team by email.
Future<Response> _addMemberHandler(Request request) async {
  try {
    final inviterId = request.context['userId'] as String?;
    if (inviterId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    final email = (body['email'] as String?)?.trim().toLowerCase();
    if (email == null || email.isEmpty) return Response(400, body: json.encode({'message': 'Email is required.'}), headers: {'Content-Type': 'application/json'});

    // If request includes a `team_name`, create a new team owned by inviter and use it.
    String? teamId;
    final requestedTeamName = (body['team_name'] as String?)?.trim();
    if (requestedTeamName != null && requestedTeamName.isNotEmpty) {
      final created = await _db.query('INSERT INTO teams (owner_id, name) VALUES (@owner, @name) RETURNING id', substitutionValues: {'owner': inviterId, 'name': requestedTeamName});
      teamId = created.first[0] as String;
      print('Team created: id=$teamId name="$requestedTeamName" owner=$inviterId');
    } else {
      // Resolve existing team id for inviter (owner preferred)
      final ownerRes = await _db.query('SELECT id FROM teams WHERE owner_id = @owner', substitutionValues: {'owner': inviterId});
      if (ownerRes.isNotEmpty) {
        teamId = ownerRes.first[0] as String;
      } else {
        final memberRes = await _db.query('SELECT team_id FROM team_members WHERE user_id = @user LIMIT 1', substitutionValues: {'user': inviterId});
        if (memberRes.isNotEmpty) teamId = memberRes.first[0] as String;
      }
    }

    if (teamId == null) return Response(400, body: json.encode({'message': 'No team found for current user.'}), headers: {'Content-Type': 'application/json'});

    final u = await _db.query('SELECT id FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': email});
    if (u.isEmpty) return Response(404, body: json.encode({'message': 'User not found.'}), headers: {'Content-Type': 'application/json'});
    final userId = u.first[0] as String;

    // Check existing membership: if already a member, return the existing member record (idempotent)
    final exists = await _db.query('SELECT id FROM team_members WHERE team_id = @team AND user_id = @user', substitutionValues: {'team': teamId, 'user': userId});
    if (exists.isNotEmpty) {
      final row = await _db.query(r'''
        SELECT tm.id AS membership_id, u.id AS user_id, u.name, u.email, tm.role, u.profile_picture_base64, tm.joined_at
        FROM team_members tm JOIN users u ON u.id = tm.user_id
        WHERE tm.team_id = @team AND tm.user_id = @user
        LIMIT 1
      ''', substitutionValues: {'team': teamId, 'user': userId});
      final m = row.first.toColumnMap();
      if (m['joined_at'] is DateTime) m['joined_at'] = (m['joined_at'] as DateTime).toIso8601String();
      return Response.ok(json.encode({'member': m, 'alreadyMember': true}), headers: {'Content-Type': 'application/json'});
    }

    await _db.query('INSERT INTO team_members (team_id, user_id, role) VALUES (@team, @user, @role)', substitutionValues: {'team': teamId, 'user': userId, 'role': 'member'});
    print('Added member to team: team=$teamId user=$userId');

    // Return the new member record
    final row = await _db.query(r'''
      SELECT tm.id AS membership_id, u.id AS user_id, u.name, u.email, tm.role, u.profile_picture_base64, tm.joined_at
      FROM team_members tm JOIN users u ON u.id = tm.user_id
      WHERE tm.team_id = @team AND tm.user_id = @user
      LIMIT 1
    ''', substitutionValues: {'team': teamId, 'user': userId});

    final m = row.first.toColumnMap();
    if (m['joined_at'] is DateTime) m['joined_at'] = (m['joined_at'] as DateTime).toIso8601String();

    return Response.ok(json.encode({'member': m}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _addMemberHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}


// Handler to return teams the user owns or is a member of.
Future<Response> _getTeamsHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final rows = await _db.query(r'''
      SELECT t.id, t.name, t.owner_id, u.name AS owner_name
      FROM teams t
      JOIN users u ON u.id = t.owner_id
      WHERE t.owner_id = @userId OR t.id IN (SELECT team_id FROM team_members WHERE user_id = @userId)
      ORDER BY LOWER(t.name) ASC
    ''', substitutionValues: {'userId': userId});

    final teams = rows.map((r) => r.toColumnMap()).toList();
    return Response.ok(json.encode(teams), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getTeamsHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler to return projects the user owns or has access to.
Future<Response> _getProjectsHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    // Projects where owner = userId OR access_type = 'everyone' OR user is in projects.team_id
    final rows = await _db.query(r'''
      SELECT p.*
      FROM projects p
      WHERE p.owner_id = @userId 
         OR p.access_type = 'everyone'
         OR (p.access_type = 'team' AND p.team_id IN (SELECT team_id FROM team_members WHERE user_id = @userId))
      ORDER BY p.created_at DESC
    ''', substitutionValues: {'userId': userId});

    final projects = rows.map((r) {
      final m = r.toColumnMap();
      if (m['created_at'] is DateTime) m['created_at'] = (m['created_at'] as DateTime).toIso8601String();
      return m;
    }).toList();

    return Response.ok(json.encode(projects), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getProjectsHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler to create a new project.
Future<Response> _createProjectHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final name = body['name'] as String?;
    final color = body['color'] as String?;
    final access = body['access'] as String?;
    final isFavorite = (body['is_favorite'] ?? false) as bool;

    if (name == null || name.isEmpty) {
      return Response(400, body: json.encode({'message': 'Project name is required.'}), headers: {'Content-Type': 'application/json'});
    }

    String accessType = 'everyone';
    String? teamId;

    if (access != null && access != 'Everyone') {
      final teamRes = await _db.query(r'''
        SELECT id FROM teams 
        WHERE LOWER(name) = LOWER(@name) 
        AND (owner_id = @userId OR id IN (SELECT team_id FROM team_members WHERE user_id = @userId))
        LIMIT 1
      ''', substitutionValues: {'name': access, 'userId': userId});
      
      if (teamRes.isNotEmpty) {
        teamId = teamRes.first[0] as String;
        accessType = 'team';
      }
    }

    final insertRes = await _db.query(r'''
      INSERT INTO projects (owner_id, name, color, access_type, team_id, is_favorite)
      VALUES (@userId, @name, @color, @accessType, @teamId, @isFavorite)
      RETURNING id
    ''', substitutionValues: {
      'userId': userId,
      'name': name,
      'color': color,
      'accessType': accessType,
      'teamId': teamId,
      'isFavorite': isFavorite,
    });

    final projectId = insertRes.first[0] as String;

    return Response.ok(json.encode({
      'success': true,
      'project': {
        'id': projectId,
        'name': name,
        'color': color,
        'access_type': accessType,
        'team_id': teamId,
        'is_favorite': isFavorite,
      }
    }), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _createProjectHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}


// Middleware to verify JWT and add user context.
Middleware _authMiddleware() {
  return (Handler innerHandler) {
    print('Auth middleware is being applied.'); // Log when middleware is set up.
    return (Request request) async {
      final authHeader = request.headers['authorization'];
      String? token;

      if (authHeader != null && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }

      if (token == null) {
        print('Auth Error: No token found.');
        return Response.unauthorized('Not authorized. No token found.');
      }

      try {
        print('Auth: Verifying token...');
        final jwt = JWT.verify(token, SecretKey(Config.jwtSecret));
        final userId = jwt.payload['id'] as String;
        print('Auth: Token verified for user ID: $userId');
        // Attach the user ID to the request context for later use.
        final updatedRequest = request.change(context: {'userId': userId});
        return await innerHandler(updatedRequest);
      } on JWTExpiredException {
        print('Auth Error: Token has expired.');
        return Response.unauthorized('Not authorized. Token has expired.');
      } on JWTException catch (err) {
        print('Auth Error: Invalid token - ${err.message}');
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
  // Also accept the legacy/vanity path '/verify-email' so email links
  // that point to the server (or manual visits) will work.
  ..get('/verify-email', _verifyHandler)
  ..post('/auth/resend-verification', _resendVerificationHandler)
  ..post('/auth/login', _loginHandler)
  ..post('/auth/request-password-reset', _requestPasswordResetHandler)
  ..post('/auth/reset-password', _resetPasswordHandler)
  // Internal test endpoint to send a test email using SMTP/app password.
  ..post('/internal/send-test-email', _sendTestEmailHandler);

// Public endpoint for invitees to set their password using the invite token.
final _publicInviteRouter = Router()
  ..post('/team/invite/set-password', _setPasswordForInviteHandler);

// Router for private endpoints that require a valid JWT.
final _privateRouter = Router()
  ..post('/filters', _createFilterHandler)
  ..get('/filters', _getFiltersHandler)
  ..patch('/filters/<id>', _updateFilterHandler)
  ..delete('/filters/<id>', _deleteFilterHandler)
  ..post('/labels', _createLabelHandler)
  ..get('/labels', _getLabelsHandler)
  ..delete('/labels/<id>', _deleteLabelHandler)
  ..post('/todos', _createTodoHandler)
  ..get('/todos', _getTodosHandler)
  ..patch('/todos/<id>', _updateTodoHandler)
  ..get('/activities', _getActivitiesHandler)
  ..put('/profile', _updateProfileHandler)
  ..post('/profile/avatar', _uploadAvatarHandler)
  ..get('/profile/avatar', _getAvatarHandler)
  ..get('/profile', _getProfileHandler)
  ..post('/team/invite', _inviteHandler)
  ..get('/team/invite/accept', _acceptInviteHandler)
  ..post('/team/check-member', _checkMemberHandler)
  ..get('/team/invited', _getInvitedMembersHandler)
  ..get('/users', _getAllUsersHandler)
  ..get('/team/members', _getTeamMembersHandler)
  ..get('/teams', _getTeamsHandler)
  ..post('/team/add-member', _addMemberHandler)
  ..get('/projects', _getProjectsHandler)
  ..post('/projects', _createProjectHandler);

// Handler for the signup request.
Future<Response> _signupHandler(Request request) async {
  try {
    // 1. Read and parse the request body from the Flutter app.
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final name = body['name'] as String?;
    var email = body['email'] as String?;
    final password = body['password'] as String?;

    // 2. Validate the incoming data.
    if (name == null || email == null || password == null || name.isEmpty || email.isEmpty || password.length < 8) {
      return Response(
        400, // Bad Request
        body: json.encode({'message': 'Name, email, and a password of at least 8 characters are required.'}),
        headers: {'Content-Type': 'application/json'},
      );
    }

    // Normalize email to lowercase for consistent, case-insensitive behavior.
    email = email?.trim().toLowerCase();

    // Prevent creating a new account if an account or pending invitation already exists for this email.
    final existingUsers = await _db.query('SELECT id FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': email});
    if (existingUsers.isNotEmpty) {
      return Response(
        409,
        body: json.encode({'message': 'An account with this email already exists. If you were invited, please use the invitation link to set your password.'}),
        headers: {'Content-Type': 'application/json'},
      );
    }

    final pendingInv = await _db.query(
      "SELECT id FROM invitations WHERE LOWER(email) = LOWER(@email) AND status != 'accepted'",
      substitutionValues: {'email': email},
    );
    if (pendingInv.isNotEmpty) {
      return Response(
        409,
        body: json.encode({'message': 'There is a pending invitation for this email. Please use the invitation link to accept and set your password.'}),
        headers: {'Content-Type': 'application/json'},
      );
    }

    // 3. Hash the password for security. NEVER store plain text passwords.
    final hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

    // 4. Generate a secure, random verification token.
    final tokenBytes = List<int>.generate(32, (_) => Random.secure().nextInt(256));
    final verificationToken = base64Url.encode(tokenBytes);
    final tokenExpiry = DateTime.now().add(const Duration(hours: 1));

    // 5. Insert the new user into the database with the token and get the new user id.
    final insertResult = await _db.query(
      r'''
      INSERT INTO users (name, email, password_hash, verification_token, verification_token_expires_at) 
      VALUES (@name, @email, @passwordHash, @token, @tokenExpiry)
      RETURNING id
      ''',
      substitutionValues: {
        'name': name,
        'email': email,
        'passwordHash': hashedPassword,
        'token': verificationToken,
        'tokenExpiry': tokenExpiry.toIso8601String(),
      },
    );
    final newUserId = insertResult.first[0] as String;

    // 5b. Insert default filters and default tags (labels) for the new user.
    await _db.transaction((tx) async {
      // Filters (time/status based views)
      await tx.query(r"""
        INSERT INTO filters (user_id, name, query, color, is_favorite, description)
        VALUES
          (@userId, 'Today', 'due_today', '#3D4CD6', true, 'Tasks due today'),
          (@userId, 'Overdue', 'overdue', '#EF4444', false, 'Past due tasks'),
          (@userId, 'This Week', 'this_week', '#F59E0B', false, 'Due in the next 7 days'),
          (@userId, 'High Priority', 'high_priority', '#D32F2F', false, 'Urgent & important tasks'),
          (@userId, 'Low Priority', 'low_priority', '#9E9E9E', false, 'Nice-to-have tasks'),
          (@userId, 'Completed', 'completed', '#2E7D32', true, 'Finished tasks'),
          (@userId, 'Assigned to Me', 'assigned_to_me', '#FF7043', false, 'Tasks assigned to you')
      """,
      substitutionValues: {'userId': newUserId});

      // Tags (labels) — create 10 handy tags for quick categorization
      await tx.query(r"""
        INSERT INTO labels (user_id, name, color, is_favorite)
        VALUES
          (@userId, 'Work', '#3D4CD6', false),
          (@userId, 'Personal', '#8E24AA', false),
          (@userId, 'Urgent', '#EF4444', false),
          (@userId, 'Meeting', '#0288D1', false),
          (@userId, 'Follow-up', '#F59E0B', false),
          (@userId, 'Finance', '#2E7D32', false),
          (@userId, 'Health', '#E91E63', false),
          (@userId, 'Learning', '#7C4DFF', false),
          (@userId, 'Shopping', '#FF7043', false),
          (@userId, 'Ideas', '#607D8B', false)
            ,(@userId, 'Default', '#9E9E9E', false)
      """,
      substitutionValues: {'userId': newUserId});
    });

    // 6. Send the verification email via Maileroo HTTP API.
    final verificationUrl = '${Config.clientBaseUrl}/verify-email?token=${Uri.encodeQueryComponent(verificationToken)}';
    final emailHtmlBody = '''
        <h1>Welcome to Klarto, $name!</h1>
        <p>Thank you for signing up. Please click the link below to verify your email address:</p>
        <p><a href="$verificationUrl">Verify My Email</a></p>
        <p>This link will expire in 1 hour.</p>
      ''';

    try {
      await EmailService.sendHtmlEmail(
        to: email!,
        subject: 'Welcome to Klarto! Please Verify Your Email',
        html: emailHtmlBody,
        fromName: 'Klarto Team',
      );
    } catch (e) {
      print('Error sending verification email: $e');
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

// Handler to resend a verification email for an existing user email.
Future<Response> _resendVerificationHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    final email = body['email'] as String?;
    if (email == null || email.trim().isEmpty) {
      return Response(400, body: json.encode({'message': 'Email is required.'}), headers: {'Content-Type': 'application/json'});
    }
    final rows = await _db.query('SELECT id, is_verified FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': email.trim()});
    if (rows.isEmpty) {
      return Response(404, body: json.encode({'message': 'No user found for that email.'}), headers: {'Content-Type': 'application/json'});
    }
    final user = rows.first.toColumnMap();
    final userId = user['id'] as String;
    final isVerified = (user['is_verified'] ?? false) as bool;
    if (isVerified) {
      return Response(400, body: json.encode({'message': 'This account is already verified.'}), headers: {'Content-Type': 'application/json'});
    }

    // Generate a new verification token
    final tokenBytes = List<int>.generate(32, (_) => Random.secure().nextInt(256));
    final verificationToken = base64Url.encode(tokenBytes);
    final tokenExpiry = DateTime.now().add(const Duration(hours: 1));

    await _db.query(
      'UPDATE users SET verification_token = @token, verification_token_expires_at = @expiry WHERE id = @id',
      substitutionValues: {'token': verificationToken, 'expiry': tokenExpiry.toIso8601String(), 'id': userId},
    );

    final verificationUrl = '${Config.clientBaseUrl}/verify-email?token=${Uri.encodeQueryComponent(verificationToken)}';
    final emailHtmlBody = '''
        <h1>Verify your email</h1>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="$verificationUrl">Verify My Email</a></p>
        <p>This link will expire in 1 hour.</p>
      ''';
    try {
      await EmailService.sendHtmlEmail(
        to: email.trim(),
        subject: 'Verify your Klarto email',
        html: emailHtmlBody,
        fromName: 'Klarto Team',
      );
    } catch (e) {
      print('Error sending verification email (resend): $e');
    }

    return Response.ok(json.encode({'message': 'Verification email sent.'}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in resend verification handler: $e');
    print(st);
    return Response.internalServerError(body: 'An unexpected error occurred.');
  }
}

// Internal handler to test SMTP email sending. Expects JSON { to, subject, body }
Future<Response> _sendTestEmailHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    final to = body['to'] as String?;
    final subject = body['subject'] as String?;
    final content = body['body'] as String?;

    if (to == null || subject == null || content == null) {
      return Response(400, body: json.encode({'message': 'to, subject and body are required in JSON'}), headers: {'Content-Type': 'application/json'});
    }

    await EmailService.sendSupportEmail(to: to, subject: subject, body: content);

    return Response.ok(json.encode({'message': 'Email sent (or queued).'}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _sendTestEmailHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Failed to send email', 'error': e.toString()}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler for the login request.
Future<Response> _loginHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    var email = body['email'] as String?;
    final password = body['password'] as String?;

    if (email == null || password == null || email.isEmpty || password.isEmpty) {
      return Response(400, body: json.encode({'message': 'Email and password are required.'}));
    }

    // Normalize email for case-insensitive matching
    email = email?.trim().toLowerCase();

    // 1. Find the user by email (case-insensitive).
    final result = await _db.query(
      'SELECT id, password_hash, is_verified FROM users WHERE LOWER(email) = @email',
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

    // Determine if this user joined via an accepted invitation
    bool joinedViaInvite = false;
    try {
      final invResult = await _db.query(
        "SELECT id FROM invitations WHERE invited_user_id = @userId AND status = 'accepted' LIMIT 1",
        substitutionValues: {'userId': userId},
      );
      joinedViaInvite = invResult.isNotEmpty;
    } catch (e) {
      print('Error checking invitations for user $userId: $e');
    }

    // Log the login activity
    _logActivity(
      userId: userId,
      activityName: 'User Login',
      description: 'User successfully logged in.',
    );

    return Response.ok(
      json.encode({'token': token, 'invited': joinedViaInvite}),
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
    var email = body['email'] as String?;

    if (email == null || email.isEmpty) {
      return Response(400, body: json.encode({'message': 'Email is required.'}));
    }

    email = email.trim().toLowerCase();

    // 1. Find user by email (case-insensitive).
    final result = await _db.query(
      'SELECT id, name FROM users WHERE LOWER(email) = @email',
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
      
      // Send password reset email using EmailService which will use Maileroo or SMTP.
      EmailService.sendHtmlEmail(
        to: email!,
        subject: 'Your Klarto Password Reset Request',
        html: emailHtmlBody,
        fromName: 'Klarto Support',
      ).catchError((e) => print('Failed to send password reset email: $e'));
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

    // Convert DateTime objects to strings before encoding
    final filters = result.map((row) {
      final map = row.toColumnMap();
      if (map['created_at'] is DateTime) {
        map['created_at'] = (map['created_at'] as DateTime).toIso8601String();
      }
      return map;
    }).toList();

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
      print('Create Filter Error: User ID is null after auth middleware.');
      return Response.forbidden('Not authorized.');
    }

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    print('Create Filter: Received body: $body');

    final name = body['name'] as String?;
    final query = body['query'] as String?;
    final color = body['color'] as String?;
    final description = body['description'] as String?; // Can be null
    final isFavorite = body['is_favorite'] as bool?;

    if (name == null || query == null || color == null || isFavorite == null) {
      print('Create Filter Error: Missing required fields.');
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

    final newFilterMap = result.first.toColumnMap();

    // Convert DateTime to a JSON-compatible string format (ISO 8601)
    if (newFilterMap['created_at'] is DateTime) {
      newFilterMap['created_at'] = (newFilterMap['created_at'] as DateTime).toIso8601String();
    }

    // Log the activity
    _logActivity(
      userId: userId,
      activityName: 'Add Filter',
      description: 'User added a new filter: "${newFilterMap['name']}"',
    );

    print('Create Filter: Successfully created filter: ${newFilterMap['id']}');
    return Response(201, body: json.encode(newFilterMap), headers: {'Content-Type': 'application/json'});

  } catch (e, stackTrace) {
    print('Error creating filter: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler to update a filter (e.g., toggle is_favorite)
Future<Response> _updateFilterHandler(Request request, String id) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    if (bodyString.isEmpty) return Response(400, body: json.encode({'message': 'Request body required.'}), headers: {'Content-Type': 'application/json'});
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final isFavorite = body['is_favorite'] as bool?;
    if (isFavorite == null) return Response(400, body: json.encode({'message': 'is_favorite (boolean) is required.'}), headers: {'Content-Type': 'application/json'});

    // Ensure ownership
    final existing = await _db.query('SELECT user_id FROM filters WHERE id = @id LIMIT 1', substitutionValues: {'id': id});
    if (existing.isEmpty) return Response(404, body: json.encode({'message': 'Filter not found.'}), headers: {'Content-Type': 'application/json'});
    final ownerId = existing.first[0] as String;
    if (ownerId != userId) return Response.forbidden('Not authorized to modify this filter.');

    final result = await _db.query(r'''
      UPDATE filters SET is_favorite = @isFavorite, created_at = created_at WHERE id = @id AND user_id = @userId RETURNING id, name, query, color, is_favorite, created_at, description
    ''', substitutionValues: {'isFavorite': isFavorite, 'id': id, 'userId': userId});

    if (result.isEmpty) return Response.internalServerError(body: json.encode({'message': 'Failed to update filter.'}), headers: {'Content-Type': 'application/json'});

    final map = result.first.toColumnMap();
    if (map['created_at'] is DateTime) map['created_at'] = (map['created_at'] as DateTime).toIso8601String();

    return Response.ok(json.encode(map), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error updating filter: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler for deleting a filter.
Future<Response> _deleteFilterHandler(Request request, String id) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }
    // Prevent deleting the default/system filter.
    final check = await _db.query(
      'SELECT name, query FROM filters WHERE id = @id AND user_id = @userId',
      substitutionValues: {'id': id, 'userId': userId},
    );
    if (check.isEmpty) {
      return Response.notFound(json.encode({'message': 'Filter not found or you do not have permission to delete it.'}), headers: {'Content-Type': 'application/json'});
    }
    final row = check.first.toColumnMap();
    final fname = (row['name'] ?? '') as String;
    final fquery = (row['query'] ?? '') as String;
    if (fquery.toLowerCase() == 'default' || fname.toLowerCase() == 'default') {
      return Response.forbidden(json.encode({'message': 'The default filter cannot be deleted.'}), headers: {'Content-Type': 'application/json'});
    }

    final result = await _db.query(
      'DELETE FROM filters WHERE id = @id AND user_id = @userId',
      substitutionValues: {'id': id, 'userId': userId},
    );

    if (result.affectedRowCount == 0) {
      return Response.notFound(json.encode({'message': 'Filter not found or you do not have permission to delete it.'}), headers: {'Content-Type': 'application/json'});
    }

    // Log the activity
    _logActivity(
      userId: userId,
      activityName: 'Delete Filter',
      description: 'User deleted a filter (ID: $id).',
    );

    return Response.ok(json.encode({'message': 'Filter deleted successfully.'}));
  } catch (e, stackTrace) {
    print('Error deleting filter: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for deleting a label.
Future<Response> _deleteLabelHandler(Request request, String id) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }
    // Prevent deleting the default/system label.
    final check = await _db.query(
      'SELECT name FROM labels WHERE id = @id AND user_id = @userId',
      substitutionValues: {'id': id, 'userId': userId},
    );
    if (check.isEmpty) {
      return Response.notFound(json.encode({'message': 'Label not found or you do not have permission to delete it.'}), headers: {'Content-Type': 'application/json'});
    }
    final lname = (check.first.toColumnMap()['name'] ?? '') as String;
    if (lname.toLowerCase() == 'default') {
      return Response.forbidden(json.encode({'message': 'The default label cannot be deleted.'}), headers: {'Content-Type': 'application/json'});
    }

    final result = await _db.query(
      'DELETE FROM labels WHERE id = @id AND user_id = @userId',
      substitutionValues: {'id': id, 'userId': userId},
    );

    if (result.affectedRowCount == 0) {
      return Response.notFound(json.encode({'message': 'Label not found or you do not have permission to delete it.'}), headers: {'Content-Type': 'application/json'});
    }

    // Log the activity
    _logActivity(
      userId: userId,
      activityName: 'Delete Label',
      description: 'User deleted a label (ID: $id).',
    );

    return Response.ok(json.encode({'message': 'Label deleted successfully.'}));
  } catch (e, stackTrace) {
    print('Error deleting label: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for getting all labels for a user.
Future<Response> _getLabelsHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }

    final result = await _db.query(
      'SELECT id, name, color, is_favorite, created_at FROM labels WHERE user_id = @userId ORDER BY created_at DESC',
      substitutionValues: {'userId': userId},
    );

    final labels = result.map((row) {
      final map = row.toColumnMap();
      if (map['created_at'] is DateTime) {
        map['created_at'] = (map['created_at'] as DateTime).toIso8601String();
      }
      return map;
    }).toList();

    return Response.ok(json.encode(labels), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error getting labels: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for creating a new label.
Future<Response> _createLabelHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final name = body['name'] as String?;
    final color = body['color'] as String?;
    final isFavorite = body['is_favorite'] as bool?;

    if (name == null || color == null || isFavorite == null) {
      return Response(400, body: json.encode({'message': 'Name, color, and is_favorite are required.'}));
    }

    final result = await _db.query(
      r'''
      INSERT INTO labels (user_id, name, color, is_favorite)
      VALUES (@userId, @name, @color, @isFavorite)
      RETURNING id, name, color, is_favorite, created_at
      ''',
      substitutionValues: {
        'userId': userId,
        'name': name,
        'color': color,
        'isFavorite': isFavorite,
      },
    );

    final newLabelMap = result.first.toColumnMap();
    if (newLabelMap['created_at'] is DateTime) {
      newLabelMap['created_at'] = (newLabelMap['created_at'] as DateTime).toIso8601String();
    }

    // Log the activity
    _logActivity(
      userId: userId,
      activityName: 'Add Label',
      description: 'User added a new label: "${newLabelMap['name']}"',
    );

    return Response(201, body: json.encode(newLabelMap), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error creating label: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for creating a new todo.
Future<Response> _createTodoHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    // Extract and validate required fields
    final title = body['title'] as String?;
    final description = body['description'] as String?;
    final projectName = body['project_name'] as String?;
    final projectId = body['project_id'] as String?;
    final dueDate = body['due_date'] as String?;
    final dueTime = body['due_time'] as String?;
    final repeatValue = body['repeat_value'] as String?;
    final priority = body['priority'] as int?;
    final labelId = body['label_id'] as String?;

    if (title == null || description == null || projectName == null || projectId == null || dueDate == null || dueTime == null || repeatValue == null || priority == null || labelId == null) {
      return Response(400, body: json.encode({'message': 'All fields are required.'}));
    }

    final result = await _db.query(
      r'''
      INSERT INTO todos (user_id, title, description, project_name, project_id, due_date, due_time, repeat_value, priority, label_id)
      VALUES (@userId, @title, @description, @projectName, @projectId, @dueDate, @dueTime, @repeatValue, @priority, @labelId)
      RETURNING *
      ''',
      substitutionValues: {
        'userId': userId,
        'title': title,
        'description': description,
        'projectName': projectName,
        'projectId': projectId,
        'dueDate': dueDate,
        'dueTime': dueTime,
        'repeatValue': repeatValue,
        'priority': priority,
        'labelId': labelId,
      },
    );

    final newTodoMap = result.first.toColumnMap();
    // Convert DateTime objects to ISO 8601 strings for JSON compatibility
    newTodoMap['created_at'] = (newTodoMap['created_at'] as DateTime).toIso8601String();
    newTodoMap['updated_at'] = (newTodoMap['updated_at'] as DateTime).toIso8601String();
    if (newTodoMap['due_date'] is DateTime) {
      newTodoMap['due_date'] = (newTodoMap['due_date'] as DateTime).toIso8601String().substring(0, 10);
    }

    // Log the activity
    _logActivity(
      userId: userId,
      activityName: 'Add Todo',
      description: 'User added a new todo: "${newTodoMap['title']}"',
    );

    return Response(201, body: json.encode(newTodoMap), headers: {'Content-Type': 'application/json'});

  } catch (e, stackTrace) {
    print('Error creating todo: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred while creating the todo.');
  }
}

// Handler for getting all todos for a user.
Future<Response> _getTodosHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }
    // Support optional filtering via ?filter=<query>. Supported filters:
    // due_today, overdue, this_week, high_priority, low_priority, completed
    final filter = request.url.queryParameters['filter']?.trim().toLowerCase();
    final clientDateStr = request.url.queryParameters['date']?.trim();

    // If the client provided a date (YYYY-MM-DD), use that for comparisons
    // to avoid server timezone issues. Otherwise fall back to CURRENT_DATE.
    final bool hasClientDate = clientDateStr != null && clientDateStr.isNotEmpty;
    String baseQuery = r'''
      SELECT 
        t.id, t.title, t.description, t.project_name, t.project_id, t.due_date, t.due_time, t.repeat_value, t.priority, t.is_completed, t.created_at,
        l.name as label_name, l.color as label_color
      FROM todos t
      LEFT JOIN labels l ON t.label_id = l.id
      WHERE t.user_id = @userId
    ''';

    // Append filter-specific conditions
    final dateExpr = hasClientDate ? "DATE(@clientDate)" : "CURRENT_DATE";

    if (filter == 'due_today' || filter == 'today') {
      baseQuery += " AND (DATE(t.due_date) = $dateExpr)";
    } else if (filter == 'overdue') {
      baseQuery += " AND t.is_completed = false AND (t.due_date IS NOT NULL AND DATE(t.due_date) < $dateExpr)";
    } else if (filter == 'this_week') {
      // Calculate week boundaries explicitly so we return only todos due within
      // the same calendar week (Mon-Sun by PostgreSQL's date_trunc('week')).
      if (hasClientDate) {
        baseQuery += " AND (t.due_date IS NOT NULL AND DATE(t.due_date) >= (DATE(date_trunc('week', DATE(@clientDate)))) AND DATE(t.due_date) < (DATE(date_trunc('week', DATE(@clientDate))) + INTERVAL '7 days'))";
      } else {
        baseQuery += " AND (t.due_date IS NOT NULL AND DATE(t.due_date) >= (DATE(date_trunc('week', CURRENT_DATE))) AND DATE(t.due_date) < (DATE(date_trunc('week', CURRENT_DATE)) + INTERVAL '7 days'))";
      }
    } else if (filter == 'high_priority') {
      baseQuery += " AND t.priority = 1";
    } else if (filter == 'low_priority') {
      baseQuery += " AND t.priority = 4";
    } else if (filter == 'completed') {
      baseQuery += " AND t.is_completed = true";
    }

    baseQuery += " ORDER BY t.created_at DESC";

    final substitutionValues = {'userId': userId};
    if (hasClientDate) substitutionValues['clientDate'] = clientDateStr;

    final result = await _db.query(baseQuery, substitutionValues: substitutionValues);

    final todos = result.map((row) {
      final map = row.toColumnMap();
      // Convert date/time objects to strings for JSON compatibility
      map['created_at'] = (map['created_at'] as DateTime).toIso8601String();
      if (map['due_date'] is DateTime) {
        map['due_date'] = (map['due_date'] as DateTime).toIso8601String().substring(0, 10);
      }
      // Add handling for due_time, which is also not directly JSON serializable.
      if (map['due_time'] != null && map['due_time'] is! String) {
        map['due_time'] = map['due_time'].toString();
      }
      return map;
    }).toList();

    return Response.ok(json.encode(todos), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error getting todos: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred while fetching todos.');
  }
}

// Handler to update a todo (partial updates supported).
Future<Response> _updateTodoHandler(Request request, String id) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    if (bodyString.isEmpty) return Response(400, body: json.encode({'message': 'Request body required.'}), headers: {'Content-Type': 'application/json'});
    final body = json.decode(bodyString) as Map<String, dynamic>;

    // Ensure the todo belongs to the user
    final existing = await _db.query('SELECT user_id, is_completed, title, description FROM todos WHERE id = @id LIMIT 1', substitutionValues: {'id': id});
    if (existing.isEmpty) return Response(404, body: json.encode({'message': 'Todo not found.'}), headers: {'Content-Type': 'application/json'});
    final ownerId = existing.first[0] as String;
    final currentlyCompleted = existing.first[1] as bool;
    if (ownerId != userId) return Response.forbidden('Not authorized to modify this todo.');

    final updates = <String, dynamic>{};
    final List<String> setClauses = [];

    if (body.containsKey('is_completed')) {
      final isCompleted = body['is_completed'] as bool?;
      if (currentlyCompleted == true && isCompleted == false) {
        return Response(400, body: json.encode({'message': 'Completed todos cannot be reopened.'}), headers: {'Content-Type': 'application/json'});
      }
      updates['isCompleted'] = isCompleted;
      setClauses.add('is_completed = @isCompleted');
    }

    if (body.containsKey('title')) {
      updates['title'] = body['title'] as String?;
      setClauses.add('title = @title');
    }

    if (body.containsKey('description')) {
      updates['description'] = body['description'] as String?;
      setClauses.add('description = @description');
    }

    if (setClauses.isEmpty) {
      return Response(400, body: json.encode({'message': 'No valid fields provided for update.'}), headers: {'Content-Type': 'application/json'});
    }

    updates['id'] = id;
    updates['userId'] = userId;
    final query = 'UPDATE todos SET ${setClauses.join(', ')}, updated_at = NOW() WHERE id = @id AND user_id = @userId RETURNING *';

    final result = await _db.query(query, substitutionValues: updates);

    if (result.isEmpty) {
      return Response.internalServerError(body: json.encode({'message': 'Failed to update todo.'}), headers: {'Content-Type': 'application/json'});
    }

    final updated = result.first.toColumnMap();
    if (updated['created_at'] is DateTime) updated['created_at'] = (updated['created_at'] as DateTime).toIso8601String();
    if (updated['updated_at'] is DateTime) updated['updated_at'] = (updated['updated_at'] as DateTime).toIso8601String();
    if (updated['due_date'] is DateTime) updated['due_date'] = (updated['due_date'] as DateTime).toIso8601String().substring(0, 10);

    // Log activity
    _logActivity(userId: userId, activityName: 'Update Todo', description: 'User updated todo $id');

    return Response.ok(json.encode(updated), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error updating todo: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler for the email verification request.
Future<Response> _verifyHandler(Request request) async {  
  final token = request.url.queryParameters['token'];

  // If no token but the client provided an `auth` JWT (or other query
  // params) — forward the full query to the client app's verify page.
  if ((token == null || token.isEmpty) && request.url.query.isNotEmpty) {
    final redirect = '${Config.clientBaseUrl}/verify-email?${request.url.query}';
    return Response.seeOther(Uri.parse(redirect));
  }

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
      // Not a simple user verification token; check if it's an invitation token.
      final invRows = await _db.query(
        'SELECT id, team_id, invited_user_id, email, invite_token_expires_at, status FROM invitations WHERE invite_token = @token',
        substitutionValues: {'token': token},
      );

      if (invRows.isEmpty) {
        return _generateHtmlResponse(
          title: 'Invalid Token',
          message: 'This verification link is not valid. It may have already been used.',
          isSuccess: false,
        );
      }

      final inv = invRows.first.toColumnMap();
      final invitationId = inv['id'] as String;
      final teamId = inv['team_id'] as String;
      final invitedUserId = inv['invited_user_id'] as String?;
      final email = inv['email'] as String;
      final expiresAt = inv['invite_token_expires_at'] as DateTime?;
      final status = inv['status'] as String?;

      if (status == 'accepted') {
        return _generateHtmlResponse(title: 'Already Accepted', message: 'This invitation was already accepted.', isSuccess: false);
      }
      if (expiresAt != null && expiresAt.isBefore(DateTime.now())) {
        return _generateHtmlResponse(title: 'Expired', message: 'This invitation has expired.', isSuccess: false);
      }

      String userId = invitedUserId ?? '';
      if (userId.isEmpty) {
        final u = await _db.query('SELECT id FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': email});
        if (u.isEmpty) {
          return _generateHtmlResponse(title: 'User Not Found', message: 'No user account found for this invitation.', isSuccess: false);
        }
        userId = u.first[0] as String;
      }

      // Mark user verified
      await _db.query('UPDATE users SET is_verified = true, verification_token = NULL, verification_token_expires_at = NULL WHERE id = @id', substitutionValues: {'id': userId});

      // Add to team if not already
      final exists = await _db.query('SELECT id FROM team_members WHERE team_id = @team AND user_id = @user', substitutionValues: {'team': teamId, 'user': userId});
      if (exists.isEmpty) {
        await _db.query('INSERT INTO team_members (team_id, user_id, role) VALUES (@team, @user, @role)', substitutionValues: {'team': teamId, 'user': userId, 'role': 'member'});
      }

      // Update invitation status
      await _db.query('UPDATE invitations SET status = @status, accepted_at = @accepted WHERE id = @id', substitutionValues: {'status': 'accepted', 'accepted': DateTime.now().toIso8601String(), 'id': invitationId});

      // Generate JWT so the user can be logged in immediately
      final jwtToken = JWT({'id': userId}).sign(SecretKey(Config.jwtSecret), expiresIn: const Duration(days: 7));
      final redirectUrl = '${Config.clientBaseUrl}/verify-email?auth=${Uri.encodeQueryComponent(jwtToken)}&inviteAccepted=1';
      return Response.seeOther(Uri.parse(redirectUrl));
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

    // If there is a pending invitation matching this token, attach user to the team
    try {
      final invRows = await _db.query('SELECT id, team_id, status FROM invitations WHERE invite_token = @token', substitutionValues: {'token': token});
      if (invRows.isNotEmpty) {
        final inv = invRows.first.toColumnMap();
        final invitationId = inv['id'] as String;
        final teamId = inv['team_id'] as String;
        final status = inv['status'] as String?;
        if (status != 'accepted') {
          final exists = await _db.query('SELECT id FROM team_members WHERE team_id = @team AND user_id = @user', substitutionValues: {'team': teamId, 'user': userId});
          if (exists.isEmpty) {
            await _db.query('INSERT INTO team_members (team_id, user_id, role) VALUES (@team, @user, @role)', substitutionValues: {'team': teamId, 'user': userId, 'role': 'member'});
          }
          await _db.query('UPDATE invitations SET status = @status, accepted_at = @accepted, invited_user_id = @uid WHERE id = @id', substitutionValues: {'status': 'accepted', 'accepted': DateTime.now().toIso8601String(), 'uid': userId, 'id': invitationId});
        }
      }
    } catch (e) {
      print('Error attaching user to team during verify flow: $e');
    }

    // Generate JWT and redirect so the user can login immediately
    final jwtToken = JWT({'id': userId}).sign(SecretKey(Config.jwtSecret), expiresIn: const Duration(days: 7));
    final redirectUrl = '${Config.clientBaseUrl}/verify-email?auth=${Uri.encodeQueryComponent(jwtToken)}';
    return Response.seeOther(Uri.parse(redirectUrl));
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

// Handler for getting all activities for a user.
Future<Response> _getActivitiesHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) {
      return Response.forbidden('Not authorized.');
    }

    // Join with users table to get the user's name for the activity log
    final result = await _db.query(
      r'''
      SELECT 
        a.id, a.activity_name, a.description, a.created_at,
        u.name as user_name 
      FROM activities a
      JOIN users u ON a.user_id = u.id
      WHERE u.id = @userId -- For now, just fetching the current user's activities.
      ORDER BY a.created_at DESC
      ''',
      substitutionValues: {'userId': userId},
    );

    final activities = result.map((row) {
      final map = row.toColumnMap();
      map['created_at'] = (map['created_at'] as DateTime).toIso8601String();
      return map;
    }).toList();

    return Response.ok(json.encode(activities), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error getting activities: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred while fetching activities.');
  }
}

// Handler for updating user profile (name).
Future<Response> _updateProfileHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    final name = body['name'] as String?;

    if (name == null || name.isEmpty) {
      return Response(400, body: json.encode({'message': 'Name is required.'}));
    }

    await _db.query(
      'UPDATE users SET name = @name WHERE id = @id',
      substitutionValues: {'name': name, 'id': userId},
    );

    _logActivity(
      userId: userId,
      activityName: 'Update Profile',
      description: 'User updated their name to: $name',
    );

    return Response.ok(json.encode({'message': 'Profile updated successfully.', 'name': name}), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error updating profile: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for uploading profile picture.
Future<Response> _uploadAvatarHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

      // Accept JSON body containing the base64 data URI for the avatar.
      // Expected body: { "avatar_base64": "data:<mime>;base64,<data>" }
      final contentTypeHeader = request.headers['content-type'] ?? '';
      String? profileBase64;

      if (contentTypeHeader.contains('application/json')) {
        final bodyString = await request.readAsString();
        try {
          final body = json.decode(bodyString) as Map<String, dynamic>;
          profileBase64 = body['avatar_base64'] as String? ?? body['avatar'] as String?;
        } catch (e) {
          return Response(400, body: json.encode({'message': 'Invalid JSON body.'}));
        }
      } else {
        return Response(400, body: json.encode({'message': 'Unsupported content type. Use application/json with avatar_base64 field.'}));
      }

      if (profileBase64 == null || profileBase64.isEmpty) {
        return Response(400, body: json.encode({'message': 'No avatar_base64 found in request.'}));
      }

      // Validate data URI and allowed mime types
        final match = RegExp(r'^data:(image\/(png|jpeg|jpg|webp));base64,(.+)', caseSensitive: false).firstMatch(profileBase64);
      // Some clients may use uppercase or omit charset; try a more lenient fallback if first pattern fails
      RegExp lateRe = RegExp(r'^data:(image\/(png|jpeg|jpg|webp));base64,(.+)', caseSensitive: false);
      final m = match ?? lateRe.firstMatch(profileBase64);
      if (m == null) {
        return Response(400, body: json.encode({'message': 'Unsupported image type or invalid data URI. Allowed: png, jpeg, webp.'}));
      }

      final encoded = m.group(3) ?? '';
      late Uint8List decodedBytes;
      try {
        decodedBytes = base64.decode(encoded);
      } catch (e) {
        return Response(400, body: json.encode({'message': 'Invalid base64 image data.'}));
      }

      // Enforce max size (1MB)
      const maxBytes = 1024 * 1024;
      if (decodedBytes.length > maxBytes) {
        return Response(413, body: json.encode({'message': 'Image too large. Max size is 1MB.'}));
      }

    await _db.query(
      'UPDATE users SET profile_picture_base64 = @b64 WHERE id = @id',
      substitutionValues: {'b64': profileBase64, 'id': userId},
    );

    _logActivity(
      userId: userId,
      activityName: 'Update Avatar',
      description: 'User updated their profile picture.',
    );

    return Response.ok(json.encode({
      'message': 'Avatar uploaded successfully.',
      'profile_picture_base64': profileBase64,
    }), headers: {'Content-Type': 'application/json'});

  } catch (e, stackTrace) {
    print('Error uploading avatar: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Helper function to log user activities.
Future<void> _logActivity({
  required String userId,
  required String activityName,
  required String description,
}) async {
  try {
    await _db.query(
      r'''
      INSERT INTO activities (user_id, activity_name, description)
      VALUES (@userId, @activityName, @description)
      ''',
      substitutionValues: {
        'userId': userId,
        'activityName': activityName,
        'description': description,
      },
    );
  } catch (e) {
    // Log the error to the console but don't let it fail the main API request.
    print('Error logging activity: $e');
  }
}

void main(List<String> args) async {
  // Load environment variables from .env (required for Config getters below)
  Config.load();
  // --- Database Connection ---
  _db = PostgreSQLConnection(
    Config.dbHost,
    Config.dbPort,
    Config.dbName,
    username: Config.dbUser,
    password: Config.dbPassword,
  );

  await _db.open();
  // Ensure required tables exist (helpful for local/dev runs where migrations
  // may not have been applied). This creates the `projects` table if missing.
  try {
    await _ensureProjectsTable();
  } catch (e, st) {
    print('Error ensuring projects table exists: $e');
    print(st);
  }
  print('Successfully connected to the database.');

  // --- Server Setup ---
  // Ensure `public` and uploads directories exist (avoids runtime errors on servers without them).
  final publicDir = Directory('public');
  if (!publicDir.existsSync()) {
    print('`public` directory not found. Creating `public`...');
    publicDir.createSync(recursive: true);
  }
  final uploadsDir = Directory(p.join('public', 'uploads'));
  if (!uploadsDir.existsSync()) {
    print('`public/uploads` directory not found. Creating `public/uploads`...');
    uploadsDir.createSync(recursive: true);
  }

  // Combine public and private routes. Apply auth middleware only to private routes.
  final cascade = Cascade()
      .add(createStaticHandler('public'))
      .add(_publicRouter)
      .add(_publicInviteRouter)
      .add(_authMiddleware()(_privateRouter));

  final handler = const Pipeline()
      .addMiddleware(logRequests()) // Log all incoming requests.
      .addMiddleware(_corsMiddleware()) // Add our new CORS middleware.
      .addHandler(cascade.handler);

  final server = await io.serve(handler, Config.host, Config.port);

  print('Server listening at http://${server.address.host}:${server.port}');
}

// Handler to retrieve user's avatar (base64) from DB
Future<Response> _getAvatarHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final result = await _db.query(
      'SELECT profile_picture_base64 FROM users WHERE id = @id',
      substitutionValues: {'id': userId},
    );

    if (result.isEmpty) return Response.notFound(json.encode({'message': 'User not found.'}));

    final row = result.first.toColumnMap();
    final b64 = row['profile_picture_base64'] as String?;
    if (b64 == null) {
      return Response.notFound(json.encode({'message': 'No avatar found.'}));
    }

    return Response.ok(json.encode({'profile_picture_base64': b64}), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error retrieving avatar: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler to invite team members (max 5 emails). Creates accounts if missing and sends invite/accept links.
Future<Response> _inviteHandler(Request request) async {
  try {
    final inviterId = request.context['userId'] as String?;
    if (inviterId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    List<String> emails = [];
    if (body['emails'] is String) {
      emails = (body['emails'] as String).split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    } else if (body['emails'] is List) {
      emails = (body['emails'] as List).map((e) => e.toString().trim()).where((s) => s.isNotEmpty).toList();
    }

    if (emails.isEmpty) return Response(400, body: json.encode({'message': 'No emails provided.'}));
    if (emails.length > 5) return Response(400, body: json.encode({'message': 'You can invite up to 5 members.'}));

    // Rate-limit: prevent abuse by limiting invites per inviter to 10 per hour
    final recentCountRes = await _db.query(
      "SELECT COUNT(*) FROM invitations WHERE inviter_id = @inviter AND created_at > (now() - interval '1 hour')",
      substitutionValues: {'inviter': inviterId},
    );
    final recentCount = (recentCountRes.isNotEmpty && recentCountRes.first.isNotEmpty) ? (recentCountRes.first[0] as int) : 0;
    if (recentCount + emails.length > 10) {
      return Response(429, body: json.encode({'message': 'Invite rate limit exceeded. Try again later.'}));
    }

    // Find or create a team for inviter.
    // Prefer a team owned by the inviter; otherwise, if the inviter is a member of a team, use that team; if none, create a new team owned by inviter.
    var teamResult = await _db.query('SELECT id FROM teams WHERE owner_id = @owner', substitutionValues: {'owner': inviterId});
    String teamId;
    if (teamResult.isEmpty) {
      // Not an owner of a team; check if inviter is a member of any team
      final memberRes = await _db.query('SELECT team_id FROM team_members WHERE user_id = @user LIMIT 1', substitutionValues: {'user': inviterId});
      if (memberRes.isNotEmpty) {
        teamId = memberRes.first[0] as String;
      } else {
        // Get inviter name for team name
        final invInfo = await _db.query('SELECT name FROM users WHERE id = @id', substitutionValues: {'id': inviterId});
        final inviterName = invInfo.isNotEmpty ? (invInfo.first[0] as String) : 'Team';
        final created = await _db.query('INSERT INTO teams (owner_id, name) VALUES (@owner, @name) RETURNING id', substitutionValues: {'owner': inviterId, 'name': "${inviterName}'s Team"});
        teamId = created.first[0] as String;
      }
    } else {
      teamId = teamResult.first[0] as String;
    }

    // Email sending will use EmailService which prefers Maileroo if configured, otherwise SMTP.

    final results = <Map<String, dynamic>>[];

    for (final email in emails) {
      final normEmail = email.trim().toLowerCase();
      // basic email validation
      if (!RegExp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").hasMatch(normEmail)) {
        results.add({'email': email, 'success': false, 'message': 'Invalid email.'});
        continue;
      }

      // avoid duplicate invites to same email within 24 hours
      final dupRes = await _db.query(
        "SELECT COUNT(*) FROM invitations WHERE LOWER(email) = LOWER(@email) AND created_at > (now() - interval '1 day')",
        substitutionValues: {'email': normEmail},
      );
      final dupCount = (dupRes.isNotEmpty && dupRes.first.isNotEmpty) ? (dupRes.first[0] as int) : 0;
      if (dupCount > 0) {
        results.add({'email': email, 'success': false, 'message': 'An invitation was already sent to this email recently.'});
        continue;
      }

      // Skip inviting self
      final inviterEmailRow = await _db.query('SELECT email FROM users WHERE id = @id', substitutionValues: {'id': inviterId});
      final inviterEmail = inviterEmailRow.isNotEmpty ? (inviterEmailRow.first[0] as String) : null;
      if (inviterEmail != null && inviterEmail.toLowerCase() == normEmail) {
        results.add({'email': email, 'success': false, 'message': 'Cannot invite yourself.'});
        continue;
      }

      // Check if user exists
      final userRows = await _db.query('SELECT id, is_verified FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': normEmail});
      String invitedUserId;
      bool existed = false;
      if (userRows.isEmpty) {
        // create a placeholder account with random password and set verification token
        final pwBytes = List<int>.generate(12, (_) => Random.secure().nextInt(256));
        final randPw = base64Url.encode(pwBytes);
        final hashed = BCrypt.hashpw(randPw, BCrypt.gensalt());
        final tokenBytes = List<int>.generate(32, (_) => Random.secure().nextInt(256));
        final inviteToken = base64Url.encode(tokenBytes);
        final tokenExpiry = DateTime.now().add(const Duration(days: 7));

        final inserted = await _db.query(
          'INSERT INTO users (name, email, password_hash, verification_token, verification_token_expires_at) VALUES (@name, @email, @passwordHash, @token, @expiry) RETURNING id',
          substitutionValues: {'name': '', 'email': normEmail, 'passwordHash': hashed, 'token': inviteToken, 'expiry': tokenExpiry.toIso8601String()},
        );
        invitedUserId = inserted.first[0] as String;

        // create invitation
        await _db.query(
          'INSERT INTO invitations (team_id, inviter_id, invited_user_id, email, invite_token, invite_token_expires_at) VALUES (@team, @inviter, @invited, @email, @token, @expiry)',
          substitutionValues: {'team': teamId, 'inviter': inviterId, 'invited': invitedUserId, 'email': normEmail, 'token': inviteToken, 'expiry': tokenExpiry.toIso8601String()},
        );

        // send invite email (will verify and add on accept)
        final acceptUrl = '${Config.clientBaseUrl}/accept-invite?token=$inviteToken';
        final emailHtmlBody = '''
            <h1>You're invited to join Klarto</h1>
            <p>An invitation was created for this email address:</p>
            <ul>
              <li><strong>Email:</strong> $email</li>
            </ul>
            <p>No password has been set for your account yet. To set a password, verify your email, and accept the invitation, click the button below:</p>
            <p><a href="$acceptUrl">Set password & Accept Invitation</a></p>
            <p>This link will expire in 7 days. If you did not expect this invitation, you can safely ignore this email.</p>
        ''';
        try {
          await EmailService.sendHtmlEmail(
            to: email!,
            subject: 'You were invited to join Klarto',
            html: emailHtmlBody,
            fromName: 'Klarto Team',
          );
          results.add({'email': email, 'success': true, 'message': 'Invitation sent (account created).'});
        } catch (e) {
          results.add({'email': email, 'success': false, 'message': 'Email send error.'});
        }
      } else {
        // user exists
        existed = true;
        invitedUserId = userRows.first[0] as String;

        // If the user is already a member of this team, skip inviting.
        final memberCheck = await _db.query(
          'SELECT id FROM team_members WHERE team_id = @team AND user_id = @user',
          substitutionValues: {'team': teamId, 'user': invitedUserId},
        );
        if (memberCheck.isNotEmpty) {
          results.add({'email': email, 'success': false, 'message': 'This person is already a member of your team.'});
          continue;
        }
        // create invite record
        final tokenBytes = List<int>.generate(32, (_) => Random.secure().nextInt(256));
        final inviteToken = base64Url.encode(tokenBytes);
        final tokenExpiry = DateTime.now().add(const Duration(days: 7));

        await _db.query(
          'INSERT INTO invitations (team_id, inviter_id, invited_user_id, email, invite_token, invite_token_expires_at) VALUES (@team, @inviter, @invited, @email, @token, @expiry)',
          substitutionValues: {'team': teamId, 'inviter': inviterId, 'invited': invitedUserId, 'email': normEmail, 'token': inviteToken, 'expiry': tokenExpiry.toIso8601String()},
        );

        final acceptUrl = '${Config.clientBaseUrl}/accept-invite?token=$inviteToken';
        final emailHtmlBody = '''
          <h1>Invitation to join Klarto</h1>
          <p>You were invited to join a Klarto team. Click the button below to verify your email and accept the invitation. If you don't have a password yet, you'll be prompted to create one during the process.</p>
          <p><a href="$acceptUrl">Verify & Accept Invitation</a></p>
          <p>This link will expire in 7 days. If you did not request this, you may ignore this message.</p>
        ''';
        try {
          await EmailService.sendHtmlEmail(
            to: email!,
            subject: 'Invitation to join Klarto',
            html: emailHtmlBody,
            fromName: 'Klarto Team',
          );
          results.add({'email': email, 'success': true, 'message': 'Invitation sent.'});
        } catch (e) {
          results.add({'email': email, 'success': false, 'message': 'Email send error.'});
        }
      }
    }

    return Response.ok(json.encode({'results': results}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _inviteHandler: $e');
    print(st);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler for invite acceptance: verifies user and adds to team, showing HTML response.
Future<Response> _acceptInviteHandler(Request request) async {
  try {
    final token = request.url.queryParameters['token'];
    if (token == null || token.isEmpty) {
      return _generateHtmlResponse(title: 'Invalid Invite', message: 'No token provided.', isSuccess: false);
    }

    final rows = await _db.query('SELECT id, team_id, invited_user_id, email, invite_token_expires_at, status FROM invitations WHERE invite_token = @token', substitutionValues: {'token': token});
    if (rows.isEmpty) return _generateHtmlResponse(title: 'Invalid or Expired', message: 'This invite is not valid.', isSuccess: false);

    final inv = rows.first.toColumnMap();
    final invitationId = inv['id'] as String;
    final teamId = inv['team_id'] as String;
    final invitedUserId = inv['invited_user_id'] as String?;
    final email = inv['email'] as String;
    final expiresAt = inv['invite_token_expires_at'] as DateTime?;
    final status = inv['status'] as String?;

    if (status == 'accepted') return _generateHtmlResponse(title: 'Already Accepted', message: 'This invitation was already accepted.', isSuccess: false);
    if (expiresAt != null && expiresAt.isBefore(DateTime.now())) return _generateHtmlResponse(title: 'Expired', message: 'This invitation has expired.', isSuccess: false);

    String userId = invitedUserId ?? '';
    if (userId.isEmpty) {
      // Try to find user by email
      final u = await _db.query('SELECT id FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': email});
      if (u.isEmpty) return _generateHtmlResponse(title: 'User Not Found', message: 'No user account found for this invitation.', isSuccess: false);
      userId = u.first[0] as String;
    }

    // Mark user verified
    await _db.query('UPDATE users SET is_verified = true, verification_token = NULL, verification_token_expires_at = NULL WHERE id = @id', substitutionValues: {'id': userId});

    // Add to team if not already
    final exists = await _db.query('SELECT id FROM team_members WHERE team_id = @team AND user_id = @user', substitutionValues: {'team': teamId, 'user': userId});
    if (exists.isEmpty) {
      await _db.query('INSERT INTO team_members (team_id, user_id, role) VALUES (@team, @user, @role)', substitutionValues: {'team': teamId, 'user': userId, 'role': 'member'});
    }

    // Update invitation status
    await _db.query('UPDATE invitations SET status = @status, accepted_at = @accepted WHERE id = @id', substitutionValues: {'status': 'accepted', 'accepted': DateTime.now().toIso8601String(), 'id': invitationId});

    return _generateHtmlResponse(title: 'Invitation Accepted', message: 'Your account has been verified and you have been added to the team.', isSuccess: true);
  } catch (e, st) {
    print('Error in _acceptInviteHandler: $e');
    print(st);
    return _generateHtmlResponse(title: 'Server Error', message: 'An unexpected error occurred.', isSuccess: false);
  }
}

// Public handler for invitees to set their password and receive a JWT.
Future<Response> _setPasswordForInviteHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    final token = body['token'] as String?;
    final password = body['password'] as String?;

    if (token == null || token.isEmpty) return Response(400, body: json.encode({'message': 'Token is required.'}));
    if (password == null || password.length < 8) return Response(400, body: json.encode({'message': 'Password must be at least 8 characters.'}));

    // Find invitation
    final invRows = await _db.query(
      'SELECT id, team_id, invited_user_id, email, invite_token_expires_at, status FROM invitations WHERE invite_token = @token',
      substitutionValues: {'token': token},
    );

    if (invRows.isEmpty) return Response(400, body: json.encode({'message': 'Invalid or expired invitation token.'}));

    final inv = invRows.first.toColumnMap();
    final invitationId = inv['id'] as String;
    final teamId = inv['team_id'] as String;
    String? invitedUserId = inv['invited_user_id'] as String?;
    final email = inv['email'] as String;
    final expiresAt = inv['invite_token_expires_at'] as DateTime?;
    final status = inv['status'] as String?;

    if (status == 'accepted') return Response(400, body: json.encode({'message': 'Invitation already accepted.'}));
    if (expiresAt != null && expiresAt.isBefore(DateTime.now())) return Response(400, body: json.encode({'message': 'Invitation has expired.'}));

    // Resolve user id
    if (invitedUserId == null || invitedUserId.isEmpty) {
      final u = await _db.query('SELECT id FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': email});
      if (u.isEmpty) return Response(400, body: json.encode({'message': 'No user account found for this invitation.'}));
      invitedUserId = u.first[0] as String;
    }

    // Update user's password and mark verified
    final hashed = BCrypt.hashpw(password, BCrypt.gensalt());
    await _db.query('UPDATE users SET password_hash = @hash, is_verified = true, verification_token = NULL, verification_token_expires_at = NULL WHERE id = @id', substitutionValues: {'hash': hashed, 'id': invitedUserId});

    // Add to team if not already
    final exists = await _db.query('SELECT id FROM team_members WHERE team_id = @team AND user_id = @user', substitutionValues: {'team': teamId, 'user': invitedUserId});
    if (exists.isEmpty) {
      await _db.query('INSERT INTO team_members (team_id, user_id, role) VALUES (@team, @user, @role)', substitutionValues: {'team': teamId, 'user': invitedUserId, 'role': 'member'});
    }

    // Update invitation
    await _db.query('UPDATE invitations SET status = @status, accepted_at = @accepted, invited_user_id = @uid WHERE id = @id', substitutionValues: {'status': 'accepted', 'accepted': DateTime.now().toIso8601String(), 'uid': invitedUserId, 'id': invitationId});

    // Generate JWT
    final jwtToken = JWT({'id': invitedUserId}).sign(SecretKey(Config.jwtSecret), expiresIn: const Duration(days: 7));

    return Response.ok(json.encode({'token': jwtToken}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _setPasswordForInviteHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

// Handler to retrieve user's profile (name, email, avatar base64)
Future<Response> _getProfileHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final result = await _db.query(
      'SELECT name, email, profile_picture_base64 FROM users WHERE id = @id',
      substitutionValues: {'id': userId},
    );

    if (result.isEmpty) return Response.notFound(json.encode({'message': 'User not found.'}));

    final row = result.first.toColumnMap();
    return Response.ok(json.encode({
      'name': row['name'],
      'email': row['email'],
      'profile_picture_base64': row['profile_picture_base64'],
    }), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error retrieving profile: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Ensure the `projects` table exists. This is a lightweight guard for
// development environments where the SQL schema may not have been applied.
Future<void> _ensureProjectsTable() async {
  try {
    await _db.query(r"""
      CREATE TABLE IF NOT EXISTS public.projects (
          id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
          owner_id uuid NOT NULL,
          name character varying(255) NOT NULL,
          color character varying(50),
          access_type character varying(20) DEFAULT 'everyone' NOT NULL,
          team_id uuid,
          is_favorite boolean DEFAULT false NOT NULL,
          created_at timestamp with time zone DEFAULT now() NOT NULL
      );
    """);
  } catch (e, st) {
    print('Failed to create projects table: $e');
    print(st);
    rethrow;
  }
}
Future<Response> _checkMemberHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    String? email;
    try {
      final body = json.decode(bodyString) as Map<String, dynamic>;
      email = body['email'] as String?;
    } catch (e) {
      email = request.url.queryParameters['email'];
    }

    if (email == null || email.isEmpty) return Response(400, body: json.encode({'message': 'Email is required.'}));

    final normEmail = email.trim().toLowerCase();

    String? teamId;
    final ownerRes = await _db.query('SELECT id FROM teams WHERE owner_id = @owner', substitutionValues: {'owner': userId});
    if (ownerRes.isNotEmpty) {
      teamId = ownerRes.first[0] as String;
    } else {
      final memberRes = await _db.query('SELECT team_id FROM team_members WHERE user_id = @user LIMIT 1', substitutionValues: {'user': userId});
      if (memberRes.isNotEmpty) teamId = memberRes.first[0] as String;
    }

    if (teamId == null) {
      return Response.ok(json.encode({'is_member': false}), headers: {'Content-Type': 'application/json'});
    }

    final u = await _db.query('SELECT id FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': normEmail});
    if (u.isEmpty) {
      return Response.ok(json.encode({'is_member': false}), headers: {'Content-Type': 'application/json'});
    }
    final otherUserId = u.first[0] as String;

    final mem = await _db.query('SELECT id FROM team_members WHERE team_id = @team AND user_id = @user', substitutionValues: {'team': teamId, 'user': otherUserId});
    final isMember = mem.isNotEmpty;

    return Response.ok(json.encode({'is_member': isMember}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _checkMemberHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}
