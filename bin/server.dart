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

Future<Response> _deleteProjectHandler(Request request, String id) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    // 1. Delete associated todos
    await _db.query('DELETE FROM todos WHERE project_id = @id::uuid', substitutionValues: {'id': id});
    
    // 2. Delete project
    final res = await _db.query('DELETE FROM projects WHERE id = @id::uuid AND owner_id = @owner::uuid', substitutionValues: {'id': id, 'owner': userId});

    if (res.affectedRowCount == 0) {
      return Response(404, body: json.encode({'message': 'Project not found or not owned by user.'}), headers: {'Content-Type': 'application/json'});
    }

    return Response.ok(json.encode({'success': true, 'message': 'Project deleted.'}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _deleteProjectHandler: $e');
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
      SELECT 'owner' AS role, u.id AS user_id, u.name, u.email, u.profile_picture_base64, t.created_at AS joined_at
      FROM teams t
      JOIN users u ON u.id = t.owner_id
      WHERE t.id = @team
      UNION ALL
      SELECT tm.role, u.id AS user_id, u.name, u.email, u.profile_picture_base64, tm.joined_at
      FROM team_members tm
      JOIN users u ON u.id = tm.user_id
      WHERE tm.team_id = @team AND tm.user_id NOT IN (SELECT owner_id FROM teams WHERE id = @team)
      ORDER BY joined_at ASC
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

    // If request includes a `team_name`, find or create a team owned by inviter.
    String? teamId;
    final requestedTeamName = (body['team_name'] as String?)?.trim();
    if (requestedTeamName != null && requestedTeamName.isNotEmpty) {
      // Check if a team with this name already exists for this owner
      final existing = await _db.query(
        'SELECT id FROM teams WHERE owner_id = @owner AND LOWER(name) = LOWER(@name)',
        substitutionValues: {'owner': inviterId, 'name': requestedTeamName},
      );
      if (existing.isNotEmpty) {
        teamId = existing.first[0] as String;
      } else {
        final created = await _db.query(
          'INSERT INTO teams (owner_id, name) VALUES (@owner, @name) RETURNING id',
          substitutionValues: {'owner': inviterId, 'name': requestedTeamName},
        );
        teamId = created.first[0] as String;
        print('Team created: id=$teamId name="$requestedTeamName" owner=$inviterId');
      }
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

    // --- Subscription Enforcement ---
    final subRows = await _db.query(r"""
      SELECT sp.member_limit 
      FROM user_subscriptions us 
      JOIN subscription_plans sp ON us.plan_id = sp.id 
      WHERE us.user_id = @userId::uuid
    """, substitutionValues: {'userId': inviterId});

    if (subRows.isEmpty) {
      return Response(402, body: json.encode({'message': 'A subscription is required to add team members.'}));
    }

    final memberLimit = subRows.first[0] as int;

    final currentMembersRes = await _db.query('SELECT COUNT(*) FROM team_members WHERE team_id = @team', substitutionValues: {'team': teamId});
    final currentMembers = currentMembersRes.first[0] as int;
    
    final pendingInvitesRes = await _db.query("SELECT COUNT(*) FROM invitations WHERE team_id = @team AND status = 'pending'", substitutionValues: {'team': teamId});
    final pendingInvites = pendingInvitesRes.first[0] as int;

    // Check if adding this user exceeds the limit (1 owner + existing + pending + this new one)
    if (1 + currentMembers + pendingInvites + 1 > memberLimit) {
      return Response(400, body: json.encode({
        'message': 'You have reached the total member limit for your plan ($memberLimit people). Please upgrade your subscription.'
      }));
    }
    // --- End Subscription Enforcement ---

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
      SELECT DISTINCT t.id, t.name, t.owner_id, u.name AS owner_name
      FROM teams t
      JOIN users u ON u.id = t.owner_id
      WHERE t.owner_id = @userId::uuid OR t.id IN (SELECT team_id FROM team_members WHERE user_id = @userId::uuid)
      ORDER BY t.name ASC
    ''', substitutionValues: {'userId': userId});

    final teams = rows.map((r) {
      final map = r.toColumnMap();
      // Ensure all values are JSON serializable (UUIDs to String)
      return map.map((key, value) => MapEntry(key, value?.toString()));
    }).toList();
    
    return Response.ok(json.encode(teams), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getTeamsHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error: $e'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler to return projects the user owns or has access to.
Future<Response> _getProjectsHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    // Projects where owner = userId OR access_type = 'everyone' OR user is in projects.team_id
    // joined_count includes all team members plus the team owner, ensuring no double counting.
    final rows = await _db.query(r'''
      SELECT p.*, t.name as team_name,
        (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = p.team_id) +
        (CASE 
          WHEN p.team_id IS NOT NULL 
          AND NOT EXISTS (
            SELECT 1 FROM team_members tm2 
            WHERE tm2.team_id = p.team_id 
            AND tm2.user_id = (SELECT owner_id FROM teams WHERE id = p.team_id)
          ) 
          THEN 1 
          ELSE 0 
        END) AS joined_count,
        (SELECT COUNT(*) FROM invitations i WHERE i.team_id = p.team_id AND i.status = 'pending') as pending_count
      FROM projects p
      LEFT JOIN teams t ON t.id = p.team_id
      WHERE p.owner_id = @userId::uuid 
         OR p.access_type = 'everyone'
         OR (p.access_type = 'team' AND p.team_id IN (SELECT team_id FROM team_members WHERE user_id = @userId::uuid))
      ORDER BY p.created_at DESC
    ''', substitutionValues: {'userId': userId});

    final projects = rows.map((r) {
      final m = r.toColumnMap();
      for (final key in m.keys.toList()) {
        final val = m[key];
        if (val is DateTime) {
          m[key] = val.toIso8601String();
        } else if (val is BigInt) {
          m[key] = val.toInt();
        } else if (val != null && val is! String && val is! int && val is! double && val is! bool) {
          m[key] = val.toString();
        }
      }
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
        final response = await innerHandler(updatedRequest);
        print('Auth: Inner handler returned status: ${response.statusCode}');
        return response;
      } on JWTExpiredException {
        print('Auth Error: Token has expired.');
        return Response.unauthorized('Not authorized. Token has expired.');
      } on JWTException catch (err) {
        print('Auth Error: Invalid token - ${err.message}');
        return Response.unauthorized('Not authorized. Invalid token: ${err.message}');
      } catch (e, st) {
        print('Auth Error: Unexpected error - $e');
        print(st);
        return Response.internalServerError(body: 'Internal Auth Error');
      }
    };
  };
}

// A global variable for the database connection.
late final PostgreSQLConnection _db;

// Combined Router for all endpoints.
final _mainRouter = Router()
  // --- Public Routes ---
  ..get('/plans', (Request request) {
    print('Public Route Accessed: /plans');
    return _getPlansHandler(request);
  })
  ..get('/plans/', (Request request) {
    print('Public Route Accessed: /plans/');
    return _getPlansHandler(request);
  })
  ..post('/auth/signup', _signupHandler)
  ..get('/auth/verify', _verifyHandler)
  ..get('/verify-email', _verifyHandler)
  ..post('/auth/resend-verification', _resendVerificationHandler)
  ..post('/auth/login', _loginHandler)
  ..post('/auth/google', _googleLoginHandler)
  ..post('/auth/request-password-reset', _requestPasswordResetHandler)
  ..post('/auth/reset-password', _resetPasswordHandler)
  ..post('/internal/send-test-email', _sendTestEmailHandler)
  ..get('/activities', _getActivitiesHandler)
  ..post('/activities', _saveActivityHandler)
  ..post('/team/invite/set-password', _setPasswordForInviteHandler)
  
  // --- Private Routes (Auth Protected) ---
  ..post('/filters', _authMiddleware()(_createFilterHandler))
  ..get('/filters', _authMiddleware()(_getFiltersHandler))
  ..patch('/filters/<id>', (Request req, String id) => _authMiddleware()((Request r) => _updateFilterHandler(r, id))(req))
  ..delete('/filters/<id>', (Request req, String id) => _authMiddleware()((Request r) => _deleteFilterHandler(r, id))(req))
  ..post('/labels', _authMiddleware()(_createLabelHandler))
  ..get('/labels', _authMiddleware()(_getLabelsHandler))
  ..put('/labels/<id>', (Request req, String id) => _authMiddleware()((Request r) => _updateLabelHandler(r, id))(req))
  ..delete('/labels/<id>', (Request req, String id) => _authMiddleware()((Request r) => _deleteLabelHandler(r, id))(req))
  ..post('/todos', _authMiddleware()(_createTodoHandler))
  ..get('/todos', _authMiddleware()(_getTodosHandler))
  ..patch('/todos/<id>', (Request req, String id) => _authMiddleware()((Request r) => _updateTodoHandler(r, id))(req))
  ..put('/profile', _authMiddleware()(_updateProfileHandler))
  ..post('/profile/avatar', _authMiddleware()(_uploadAvatarHandler))
  ..get('/profile/avatar', _authMiddleware()(_getAvatarHandler))
  ..get('/profile', _authMiddleware()(_getProfileHandler))
  ..get('/profile/', _authMiddleware()(_getProfileHandler))
  ..post('/complete-onboarding', _authMiddleware()(_completeOnboardingHandler))
  ..post('/team/invite', _authMiddleware()(_inviteHandler))
  ..get('/team/invite/accept', _authMiddleware()(_acceptInviteHandler))
  ..post('/team/check-member', _authMiddleware()(_checkMemberHandler))
  ..get('/team/invited', _authMiddleware()(_getInvitedMembersHandler))
  ..get('/users', _authMiddleware()(_getAllUsersHandler))
  ..get('/team/members', _authMiddleware()(_getTeamMembersHandler))
  ..get('/teams', _authMiddleware()(_getTeamsHandler))
  ..post('/teams', _authMiddleware()(_createTeamHandler))
  ..delete('/team/<name>', (Request req, String name) => _authMiddleware()((Request r) => _deleteTeamHandler(r, name))(req))
  ..post('/team/add-member', _authMiddleware()(_addMemberHandler))
  ..get('/projects', _authMiddleware()(_getProjectsHandler))
  ..post('/projects', _authMiddleware()(_createProjectHandler))
  ..delete('/projects/<id>', (Request req, String id) => _authMiddleware()((Request r) => _deleteProjectHandler(r, id))(req))
  ..get('/notes', _authMiddleware()(_getNotesHandler))
  ..post('/notes', _authMiddleware()(_addNoteHandler))
  ..post('/todos/comments', _authMiddleware()(_addCommentHandler))
  ..get('/todos/<id>/comments', (Request req, String id) => _authMiddleware()((Request r) => _getCommentsHandler(r, id))(req))
  ..post('/todos/sub-todos', _authMiddleware()(_addSubTodoHandler))
  ..get('/todos/<id>/sub-todos', (Request req, String id) => _authMiddleware()((Request r) => _getSubTodosHandler(r, id))(req))
  ..patch('/todos/sub-todos/<id>/toggle', (Request req, String id) => _authMiddleware()((Request r) => _toggleSubTodoHandler(r, id))(req))
  ..patch('/todos/sub-todos/<id>', (Request req, String id) => _authMiddleware()((Request r) => _updateSubTodoHandler(r, id))(req))
  ..get('/subscription', _authMiddleware()(_getCurrentSubscriptionHandler))
  ..post('/subscribe', _authMiddleware()(_subscribeHandler));

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
    await _initializeUserData(newUserId);

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
/// Updates the subscription status from Stripe for a given user (owner).
Future<String> _syncSubscriptionStatus(String ownerId) async {
  try {
    final subRes = await _db.query('SELECT stripe_subscription_id, status FROM user_subscriptions WHERE user_id = @id::uuid', substitutionValues: {'id': ownerId});
    if (subRes.isEmpty) return 'none';
    
    final stripeSubId = subRes.first[0] as String?;
    if (stripeSubId == null || stripeSubId.isEmpty) return 'none';

    final resp = await http.get(
      Uri.parse('https://api.stripe.com/v1/subscriptions/$stripeSubId'),
      headers: {'Authorization': 'Bearer ${Config.stripeSecretKey}'},
    );

    if (resp.statusCode == 200) {
      final data = json.decode(resp.body);
      final newStatus = data['status'] as String;
      
      // Update DB if changed
      await _db.query('UPDATE user_subscriptions SET status = @status WHERE user_id = @id::uuid', substitutionValues: {'status': newStatus, 'id': ownerId});
      return newStatus;
    }
  } catch (e) {
    print('Error syncing subscription status: $e');
  }
  return 'error';
}

/// Checks if the user or their team owner has an active subscription.
Future<bool> _hasActiveSubscription(String userId) async {
  try {
    // 1. Find the "subscription owner" (the person responsible for payment)
    String ownerId = userId;
    
    // Check if user is a member of someone else's team
    final memberRes = await _db.query('SELECT team_id FROM team_members WHERE user_id = @userId::uuid LIMIT 1', substitutionValues: {'userId': userId});
    if (memberRes.isNotEmpty) {
      final teamId = memberRes.first[0] as String;
      final teamData = await _db.query('SELECT owner_id FROM teams WHERE id = @teamId::uuid', substitutionValues: {'teamId': teamId});
      if (teamData.isNotEmpty) {
        ownerId = teamData.first[0] as String;
      }
    }

    // 2. See if the owner has a subscription
    final subStatus = await _syncSubscriptionStatus(ownerId);
    
    // Allow 'active' or 'trialing'
    if (subStatus == 'active' || subStatus == 'trialing') return true;
    
    // If no subscription recorded yet, check if they are still onboarding
    if (subStatus == 'none') {
      final userRes = await _db.query('SELECT has_completed_onboarding FROM users WHERE id = @userId::uuid', substitutionValues: {'userId': userId});
      if (userRes.isNotEmpty && !(userRes.first[0] as bool)) {
        return true; // Allow login to complete onboarding
      }
      return false; // Subscription required for completed users
    }

    return false; // past_due, unpaid, canceled, etc.
  } catch (e) {
    print('Error in _hasActiveSubscription: $e');
    return true; // Fail open to avoid locking everyone out on db error? Or fail closed for security? User said "cannot login" if fail.
  }
}

Future<Response> _loginHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    var email = body['email'] as String?;
    final password = body['password'] as String?;

    if (email == null || password == null || email.isEmpty || password.isEmpty) {
      return Response(400, body: json.encode({'message': 'Email and password are required.'}));
    }

    // normalization 
    email = email?.trim().toLowerCase();

    // 1. Find the user by email (case-insensitive).
    final result = await _db.query(
      'SELECT id, password_hash, is_verified, has_completed_onboarding FROM users WHERE LOWER(email) = @email',
      substitutionValues: {'email': email},
    );

    if (result.isEmpty) {
      return Response(401, body: json.encode({'message': 'Invalid email or password.'}));
    }

    final user = result.first;
    final userId = user[0] as String;

    // --- Subscription Check ---
    final isActive = await _hasActiveSubscription(userId);
    if (!isActive) {
      return Response(402, body: json.encode({
        'message': 'Your subscription is inactive or payment has failed. Please contact the team owner to resolve payment issues.'
      }));
    }
    // --- End Subscription Check ---

    final storedHash = user[1] as String;
    final isVerified = user[2] as bool;
    final hasCompletedOnboarding = user[3] as bool;

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
      json.encode({
        'token': token,
        'user_id': userId,
        'invited': joinedViaInvite,
        'has_completed_onboarding': hasCompletedOnboarding,
      }),
      headers: {'Content-Type': 'application/json'},
    );

  } catch (e, stackTrace) {
    print('Error during login: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

Future<Response> _googleLoginHandler(Request request) async {
  try {
    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final idToken = body['idToken'] as String?;

    if (idToken == null || idToken.isEmpty) {
      return Response(400,
          body: json.encode({'message': 'Google ID Token is required.'}),
          headers: {'Content-Type': 'application/json'});
    }

    // Verify token with Google
    final List<String> issuers = [
      'https://accounts.google.com',
      'accounts.google.com'
    ];
    
    final googleVerifyUrl = 'https://oauth2.googleapis.com/tokeninfo?id_token=$idToken';
    final googleResponse = await http.get(Uri.parse(googleVerifyUrl));
    
    if (googleResponse.statusCode != 200) {
      return Response(401,
          body: json.encode({'message': 'Invalid Google Token.'}),
          headers: {'Content-Type': 'application/json'});
    }

    final payload = json.decode(googleResponse.body) as Map<String, dynamic>;
    
    // Safety check: is it actually from Google?
    if (!issuers.contains(payload['iss'])) {
       return Response(401,
          body: json.encode({'message': 'Invalid Token Issuer.'}),
          headers: {'Content-Type': 'application/json'});
    }

    final email = payload['email'] as String?;
    final name = payload['name'] as String?;
    final profilePicture = payload['picture'] as String?;
    final emailVerified = payload['email_verified'] == 'true' || payload['email_verified'] == true;

    if (email == null || !emailVerified) {
      return Response(400,
          body: json.encode({'message': 'Unverified or missing email from Google.'}),
          headers: {'Content-Type': 'application/json'});
    }

    final normalizedEmail = email.trim().toLowerCase();

    // 1. Check if the user exists
    final result = await _db.query(
      'SELECT id, is_verified, has_completed_onboarding, name FROM users WHERE LOWER(email) = @email',
      substitutionValues: {'email': normalizedEmail},
    );

    String userId;
    bool hasCompletedOnboarding = false;

    if (result.isEmpty) {
      // 2. Create new user if not exists (This user is an "Owner" by default unless invited)
      final randomPassword = Random().nextInt(1000000).toString();
      final passwordHash = BCrypt.hashpw(randomPassword, BCrypt.gensalt());

      final insertResult = await _db.query(
        r'''
        INSERT INTO users (name, email, password_hash, is_verified, has_completed_onboarding, profile_picture_base64)
        VALUES (@name, @email, @passwordHash, true, false, @profilePicture)
        RETURNING id
        ''',
        substitutionValues: {
          'name': name ?? email.split('@')[0],
          'email': normalizedEmail,
          'passwordHash': passwordHash,
          'profilePicture': profilePicture,
        },
      );
      userId = insertResult.first[0] as String;
      hasCompletedOnboarding = false;

      // Insert default filters and labels for the new user
      await _initializeUserData(userId);

      _logActivity(
        userId: userId,
        activityName: 'User Signup (Google)',
        description: 'New user registered via Google Social Login.',
      );
    } else {
      // 3. User exists, just login
      userId = result.first[0] as String;
      final bool alreadyVerified = result.first[1] as bool;
      hasCompletedOnboarding = result.first[2] as bool;
      final existingName = result.first[3] as String?;

      // Ensure user has default filters and labels (especially if they were invited)
      await _initializeUserData(userId);

      // If they exist but weren't verified (e.g. placeholder from invitation), verify them now
      if (!alreadyVerified) {
        await _db.query(
          'UPDATE users SET is_verified = true, name = @name, profile_picture_base64 = @profilePicture WHERE id = @id::uuid',
          substitutionValues: {
            'id': userId,
            'name': (existingName == null || existingName.isEmpty)
                ? (name ?? email.split('@')[0])
                : existingName,
            'profilePicture': profilePicture,
          },
        );
      }

      _logActivity(
        userId: userId,
        activityName: 'User Login (Google)',
        description: 'User successfully logged in via Google.',
      );
    }

    // --- Subscription Check ---
    final isActive = await _hasActiveSubscription(userId);
    if (!isActive && hasCompletedOnboarding) {
      return Response(402, body: json.encode({
        'message': 'Your subscription is inactive or payment has failed. Please contact the team owner.'
      }), headers: {'Content-Type': 'application/json'});
    }
    // --- End Subscription Check ---

    // 4. Handle Pending Invitations (Auto-accept)
    final pendingInvites = await _db.query(
      "SELECT id, team_id FROM invitations WHERE LOWER(email) = @email AND status = 'pending'",
      substitutionValues: {'email': normalizedEmail},
    );

    for (final invite in pendingInvites) {
      final inviteId = invite[0] as String;
      final teamId = invite[1] as String;

      // Update invitation status
      await _db.query(
        "UPDATE invitations SET status = 'accepted', accepted_at = now(), invited_user_id = @userId::uuid WHERE id = @inviteId::uuid",
        substitutionValues: {'userId': userId, 'inviteId': inviteId},
      );

      // Add to team_members
      await _db.query(
        "INSERT INTO team_members (team_id, user_id, role) VALUES (@teamId::uuid, @userId::uuid, 'member') ON CONFLICT DO NOTHING",
        substitutionValues: {'teamId': teamId, 'userId': userId},
      );
    }

    // 5. Generate a JWT.
    final jwt = JWT({'id': userId});
    final token = jwt.sign(SecretKey(Config.jwtSecret),
        expiresIn: const Duration(days: 7));

    // Determine if this user is a "Member" (joined via invitation)
    bool isMember = false;
    final teamMemberCheck = await _db.query(
      "SELECT id FROM team_members WHERE user_id = @userId::uuid LIMIT 1",
      substitutionValues: {'userId': userId},
    );
    isMember = teamMemberCheck.isNotEmpty;

    return Response.ok(
      json.encode({
        'token': token,
        'user_id': userId,
        'invited': isMember,
        'has_completed_onboarding': hasCompletedOnboarding,
      }),
      headers: {'Content-Type': 'application/json'},
    );
  } catch (e, stackTrace) {
    print('Error during Google login: $e');
    print(stackTrace);
    return Response.internalServerError(
        body: 'An unexpected server error occurred.');
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
      'SELECT id, name, query, color, is_favorite, created_at, description FROM filters WHERE user_id = @userId::uuid ORDER BY created_at DESC',
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
      VALUES (@userId::uuid, @name, @query, @color, @isFavorite, @description)
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
    final existing = await _db.query('SELECT user_id FROM filters WHERE id = @id::uuid LIMIT 1', substitutionValues: {'id': id});
    if (existing.isEmpty) return Response(404, body: json.encode({'message': 'Filter not found.'}), headers: {'Content-Type': 'application/json'});
    final ownerId = existing.first[0] as String;
    if (ownerId != userId) return Response.forbidden('Not authorized to modify this filter.');

    final result = await _db.query(r'''
      UPDATE filters SET is_favorite = @isFavorite, created_at = created_at WHERE id = @id::uuid AND user_id = @userId::uuid RETURNING id, name, query, color, is_favorite, created_at, description
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
      'SELECT name, query FROM filters WHERE id = @id::uuid AND user_id = @userId::uuid',
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
      'DELETE FROM filters WHERE id = @id::uuid AND user_id = @userId::uuid',
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
      'SELECT name FROM labels WHERE id = @id::uuid AND user_id = @userId::uuid',
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
      'DELETE FROM labels WHERE id = @id::uuid AND user_id = @userId::uuid',
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
      'SELECT id, name, color, is_favorite, created_at FROM labels WHERE user_id = @userId::uuid ORDER BY created_at DESC',
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
      VALUES (@userId::uuid, @name, @color, @isFavorite)
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

// Handler for updating an existing label.
Future<Response> _updateLabelHandler(Request request, String id) async {
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

    // Validate that the label belongs to the user
    final existingLabel = await _db.query(
      'SELECT id FROM labels WHERE id = @id::uuid AND user_id = @userId::uuid LIMIT 1',
      substitutionValues: {'id': id, 'userId': userId},
    );

    if (existingLabel.isEmpty) {
      return Response(404, body: json.encode({'message': 'Label not found or not owned by you.'}));
    }

    final result = await _db.query(
      r'''
      UPDATE labels
      SET name = @name, color = @color, is_favorite = @isFavorite
      WHERE id = @id::uuid AND user_id = @userId::uuid
      RETURNING id, name, color, is_favorite, created_at
      ''',
      substitutionValues: {
        'id': id,
        'userId': userId,
        'name': name,
        'color': color,
        'isFavorite': isFavorite,
      },
    );

    if (result.isEmpty) {
      return Response(400, body: json.encode({'message': 'Update failed.'}));
    }

    final updatedLabelMap = result.first.toColumnMap();
    if (updatedLabelMap['created_at'] is DateTime) {
      updatedLabelMap['created_at'] = (updatedLabelMap['created_at'] as DateTime).toIso8601String();
    }

    return Response.ok(json.encode(updatedLabelMap), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error updating label: $e');
    print(stackTrace);
    return Response.internalServerError(body: json.encode({'message': 'An unexpected server error occurred.'}), headers: {'Content-Type': 'application/json'});
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
      VALUES (@userId::uuid, @title, @description, @projectName, @projectId::uuid, @dueDate, @dueTime, @repeatValue, @priority, @labelId::uuid)
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
    final projectId = request.url.queryParameters['project_id']?.trim();

    // If the client provided a date (YYYY-MM-DD), use that for comparisons
    // to avoid server timezone issues. Otherwise fall back to CURRENT_DATE.
    final bool hasClientDate = clientDateStr != null && clientDateStr.isNotEmpty;
    String baseQuery = r'''
      SELECT 
        t.id, t.title, t.description, t.project_name, t.project_id, t.team_id, t.due_date, t.due_time, t.repeat_value, t.priority, t.is_completed, t.created_at,
        l.name as label_name, l.color as label_color,
        tm.name as team_name
      FROM todos t
      LEFT JOIN labels l ON t.label_id = l.id AND l.user_id = @userId::uuid
      LEFT JOIN teams tm ON t.team_id = tm.id
      WHERE (
        t.user_id = @userId::uuid 
        OR 
        t.team_id IN (SELECT team_id FROM team_members WHERE user_id = @userId::uuid)
        OR
        t.project_id IN (
           SELECT p.id FROM projects p 
           WHERE p.owner_id = @userId::uuid 
              OR p.access_type = 'everyone' 
              OR (p.access_type = 'team' AND p.team_id IN (SELECT team_id FROM team_members WHERE user_id = @userId::uuid))
        )
      )
    ''';

    if (projectId != null && projectId.isNotEmpty) {
      baseQuery += " AND t.project_id = @projectId::uuid";
    }

    // Append filter-specific conditions
    final dateExpr = hasClientDate ? "DATE(@clientDate)" : "CURRENT_DATE";

    if (filter == 'completed') {
      baseQuery += " AND t.is_completed = true";
    } else {
      // For ALL other lists, only show incomplete tasks
      baseQuery += " AND t.is_completed = false";

      if (filter == 'due_today' || filter == 'today') {
        baseQuery += " AND (DATE(t.due_date) = $dateExpr)";
      } else if (filter == 'overdue') {
        baseQuery += " AND (t.due_date IS NOT NULL AND DATE(t.due_date) < $dateExpr)";
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
      }
    }

    baseQuery += " ORDER BY t.created_at DESC";

    final substitutionValues = <String, dynamic>{'userId': userId};
    if (hasClientDate) substitutionValues['clientDate'] = clientDateStr;
    if (projectId != null && projectId.isNotEmpty) substitutionValues['projectId'] = projectId;

    final result = await _db.query(baseQuery, substitutionValues: substitutionValues);

    final todos = result.map((row) {
      final map = <String, dynamic>{};
      for (var i = 0 ; i < result.columnDescriptions.length; i++) {
        map[result.columnDescriptions[i].columnName] = row[i];
      }
      // Ensure all values are JSON serializable
      return map.map((key, value) {
        if (value is DateTime) {
          if (key == 'due_date') {
            return MapEntry(key, value.toIso8601String().substring(0, 10));
          }
          return MapEntry(key, value.toIso8601String());
        }
        if (value != null && value is! String && value is! int && value is! double && value is! bool) {
          return MapEntry(key, value.toString());
        }
        return MapEntry(key, value);
      });
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
    final existing = await _db.query('SELECT user_id, is_completed, title, description FROM todos WHERE id = @id::uuid LIMIT 1', substitutionValues: {'id': id});
    if (existing.isEmpty) return Response(404, body: json.encode({'message': 'Todo not found.'}), headers: {'Content-Type': 'application/json'});
    final ownerId = existing.first[0] as String;
    final currentlyCompleted = existing.first[1] as bool;
    if (ownerId != userId) return Response.forbidden('Not authorized to modify this todo.');

    final updates = <String, dynamic>{};
    final List<String> setClauses = [];

    if (body.containsKey('is_completed')) {
      updates['isCompleted'] = body['is_completed'] as bool?;
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

    if (body.containsKey('due_date')) {
      updates['dueDate'] = body['due_date'];
      setClauses.add('due_date = @dueDate');
    }

    if (body.containsKey('priority')) {
      updates['priority'] = body['priority'];
      setClauses.add('priority = @priority');
    }

    if (body.containsKey('label_id')) {
      updates['labelId'] = body['label_id'];
      setClauses.add('label_id = @labelId::uuid');
    }

    if (body.containsKey('project_name')) {
      updates['projectName'] = body['project_name'];
      setClauses.add('project_name = @projectName');
    }

    if (body.containsKey('project_id')) {
      updates['projectId'] = body['project_id'];
      setClauses.add('project_id = @projectId::uuid');
    }

    if (body.containsKey('team_id')) {
      updates['teamId'] = body['team_id'];
      if (updates['teamId'] == null) {
        setClauses.add('team_id = NULL');
      } else {
        setClauses.add('team_id = @teamId::uuid');
      }
    }

    if (setClauses.isEmpty) {
      return Response(400, body: json.encode({'message': 'No valid fields provided for update.'}), headers: {'Content-Type': 'application/json'});
    }

    updates['id'] = id;
    updates['userId'] = userId;
    final query = 'UPDATE todos SET ${setClauses.join(', ')}, updated_at = NOW() WHERE id = @id::uuid AND user_id = @userId::uuid RETURNING *';

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
      await _db.query('UPDATE users SET is_verified = true, verification_token = NULL, verification_token_expires_at = NULL WHERE id = @id::uuid', substitutionValues: {'id': userId});

      // Add to team if not already
      final exists = await _db.query('SELECT id FROM team_members WHERE team_id = @team::uuid AND user_id = @user::uuid', substitutionValues: {'team': teamId, 'user': userId});
      if (exists.isEmpty) {
        await _db.query('INSERT INTO team_members (team_id, user_id, role) VALUES (@team::uuid, @user::uuid, @role)', substitutionValues: {'team': teamId, 'user': userId, 'role': 'member'});
      }

      // Update invitation status
      await _db.query('UPDATE invitations SET status = @status, accepted_at = @accepted WHERE id = @id::uuid', substitutionValues: {'status': 'accepted', 'accepted': DateTime.now().toIso8601String(), 'id': invitationId});

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
      'UPDATE users SET is_verified = true, verification_token = NULL, verification_token_expires_at = NULL WHERE id = @id::uuid',
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
          final exists = await _db.query('SELECT id FROM team_members WHERE team_id = @team::uuid AND user_id = @user::uuid', substitutionValues: {'team': teamId, 'user': userId});
          if (exists.isEmpty) {
            await _db.query('INSERT INTO team_members (team_id, user_id, role) VALUES (@team::uuid, @user::uuid, @role)', substitutionValues: {'team': teamId, 'user': userId, 'role': 'member'});
          }
          await _db.query('UPDATE invitations SET status = @status, accepted_at = @accepted, invited_user_id = @uid::uuid WHERE id = @id::uuid', substitutionValues: {'status': 'accepted', 'accepted': DateTime.now().toIso8601String(), 'uid': userId, 'id': invitationId});
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
    final queryParams = request.url.queryParameters;
    final userId = queryParams['user_id'];

    if (userId == null) {
      return Response.badRequest(
          body: json.encode({'error': 'user_id is required'}),
          headers: {'Content-Type': 'application/json'});
    }

    // Join with users table to get the user's name for the activity log
    final result = await _db.query(
      r'''
      SELECT 
        a.id, a.activity_name, a.description, a.created_at,
        u.name as user_name 
      FROM activities a
      JOIN users u ON a.user_id = u.id
      WHERE u.id = @userId::uuid 
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

Future<Response> _saveActivityHandler(Request request) async {
  try {
    final body = await request.readAsString();
    final data = json.decode(body);
    final userId = data['user_id'];
    final activityName = data['activity_name'];
    final description = data['description'];

    if (userId == null || activityName == null || description == null) {
      return Response.badRequest(
          body: json.encode({'error': 'user_id, activity_name, and description are required'}),
          headers: {'Content-Type': 'application/json'});
    }

    await _logActivity(
      userId: userId,
      activityName: activityName,
      description: description,
    );

    return Response.ok(json.encode({'success': true}),
        headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _saveActivityHandler: $e');
    print(st);
    return Response.internalServerError(
        body: json.encode({'message': 'Server error: $e'}),
        headers: {'Content-Type': 'application/json'});
  }
}

// Handler for updating user profile (name).
Future<Response> _updateProfileHandler(Request request) async {
  print('Entering _updateProfileHandler...');
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
      'UPDATE users SET name = @name WHERE id = @id::uuid',
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
      'UPDATE users SET profile_picture_base64 = @b64 WHERE id = @id::uuid',
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
      VALUES (@userId::uuid, @activityName, @description)
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

// Handler to create a new team with a list of initial members.
Future<Response> _createTeamHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;
    final teamName = (body['name'] as String?)?.trim();
    final memberEmails = (body['members'] as List<dynamic>?) ?? [];

    if (teamName == null || teamName.isEmpty) {
      return Response(400, body: json.encode({'message': 'Team name is required.'}), headers: {'Content-Type': 'application/json'});
    }

    // 1. Create the team
    final teamRes = await _db.query(
      'INSERT INTO teams (owner_id, name) VALUES (@owner::uuid, @name) RETURNING id',
      substitutionValues: {'owner': userId, 'name': teamName},
    );
    final teamId = teamRes.first[0].toString();

    // 2. Add members
    for (final emailObj in memberEmails) {
      final email = emailObj.toString().trim().toLowerCase();
      if (email.isEmpty) continue;

      final u = await _db.query('SELECT id FROM users WHERE LOWER(email) = LOWER(@email)', substitutionValues: {'email': email});
      if (u.isNotEmpty) {
        final memberUserId = u.first[0].toString();
        // Don't add owner to team_members specifically if they are already identified as owner in team retrieval
        if (memberUserId != userId) {
          await _db.query(
            'INSERT INTO team_members (team_id, user_id, role) VALUES (@team::uuid, @user::uuid, @role) ON CONFLICT DO NOTHING',
            substitutionValues: {'team': teamId, 'user': memberUserId, 'role': 'member'},
          );
        }
      }
    }

    return Response.ok(json.encode({'success': true, 'teamId': teamId, 'name': teamName}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _createTeamHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}), headers: {'Content-Type': 'application/json'});
  }
}

// Handler to delete a team by name (requested by current owner).
Future<Response> _deleteTeamHandler(Request request, String name) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    // Only allow owner to delete the team.
    final teamRes = await _db.query(
      'SELECT id FROM teams WHERE owner_id = @owner AND name = @name',
      substitutionValues: {'owner': userId, 'name': Uri.decodeComponent(name)},
    );

    if (teamRes.isEmpty) {
      return Response.notFound(json.encode({'message': 'Team not found or you are not the owner.'}));
    }

    final teamId = teamRes.first[0] as String;

    // Delete members, invitations, projects, and finally the team.
    await _db.query('DELETE FROM team_members WHERE team_id = @id', substitutionValues: {'id': teamId});
    await _db.query('DELETE FROM invitations WHERE team_id = @id', substitutionValues: {'id': teamId});
    // Optional: Delete projects associated with this team? 
    // Usually it's better to keep them or reassign. For now, let's just clear team_id from projects.
    await _db.query('UPDATE projects SET team_id = NULL, access_type = \'everyone\' WHERE team_id = @id', substitutionValues: {'id': teamId});
    await _db.query('DELETE FROM teams WHERE id = @id', substitutionValues: {'id': teamId});

    return Response.ok(json.encode({'success': true, 'message': 'Team deleted successfully.'}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _deleteTeamHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

// Handler to retrieve notes for the current user.
Future<Response> _getNotesHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final rows = await _db.query(
      'SELECT id, type, content, media_base64, created_at FROM notes WHERE user_id = @userId ORDER BY created_at ASC',
      substitutionValues: {'userId': userId},
    );

    final notes = rows.map((r) {
      final m = r.toColumnMap();
      if (m['created_at'] is DateTime) m['created_at'] = (m['created_at'] as DateTime).toIso8601String();
      return m;
    }).toList();

    return Response.ok(json.encode(notes), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getNotesHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

// Handler to add a new note (text, image, or audio).
Future<Response> _addNoteHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final bodyString = await request.readAsString();
    final body = json.decode(bodyString) as Map<String, dynamic>;

    final type = body['type'] as String? ?? 'text'; // text, image, audio
    final content = body['content'] as String? ?? '';
    final mediaBase64 = body['media_base64'] as String?; // Base64 data

    await _db.query(
      'INSERT INTO notes (user_id, type, content, media_base64) VALUES (@user, @type, @content, @media)',
      substitutionValues: {
        'user': userId,
        'type': type,
        'content': content,
        'media': mediaBase64,
      },
    );

    return Response.ok(json.encode({'success': true}), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _addNoteHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

void main(List<String> args) async {
  print('--- SERVER STARTING [v1.0.3 - 18:25] ---');
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
    await _ensureOnboardingColumn();
    await _ensureNotesTable();
    await _ensureCommentsTable();
    await _ensureSubTodosTable();
    await _ensureSubscriptionTables();
  } catch (e, st) {
    print('Error ensuring database schema is up to date: $e');
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

  // Combine static files with the main router.
  final cascade = Cascade()
      .add(_mainRouter)
      .add(createStaticHandler('public'));

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
      'SELECT profile_picture_base64 FROM users WHERE id = @id::uuid',
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
    
    // --- Subscription Enforcement ---
    final subRows = await _db.query(r"""
      SELECT sp.member_limit 
      FROM user_subscriptions us 
      JOIN subscription_plans sp ON us.plan_id = sp.id 
      WHERE us.user_id = @userId::uuid
    """, substitutionValues: {'userId': inviterId});

    if (subRows.isEmpty) {
      return Response(402, body: json.encode({'message': 'A subscription is required to invite team members.'}));
    }

    final memberLimit = subRows.first[0] as int;

    // Count existing members + pending invites
    // First, find the team this user owns
    final teamRes = await _db.query('SELECT id FROM teams WHERE owner_id = @owner', substitutionValues: {'owner': inviterId});
    String? currentTeamId;
    if (teamRes.isNotEmpty) {
      currentTeamId = teamRes.first[0] as String;
    }

    if (currentTeamId != null) {
      final currentMembersRes = await _db.query('SELECT COUNT(*) FROM team_members WHERE team_id = @team', substitutionValues: {'team': currentTeamId});
      final currentMembers = currentMembersRes.first[0] as int;
      
      final pendingInvitesRes = await _db.query("SELECT COUNT(*) FROM invitations WHERE team_id = @team AND status = 'pending'", substitutionValues: {'team': currentTeamId});
      final pendingInvites = pendingInvitesRes.first[0] as int;

      // The limit includes the owner + all members (invited and joined)
      if (1 + currentMembers + pendingInvites + emails.length > memberLimit) {
        return Response(400, body: json.encode({
          'message': 'You have reached the total member limit for your plan ($memberLimit people). Please upgrade your subscription.'
        }));
      }
    }
    // --- End Subscription Enforcement ---

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

    // Ensure the invited user has their default filters and labels
    await _initializeUserData(invitedUserId);

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
  print('Entering _getProfileHandler...');
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final result = await _db.query(
      'SELECT name, email, profile_picture_base64, has_completed_onboarding FROM users WHERE id = @id::uuid',
      substitutionValues: {'id': userId},
    );

    if (result.isEmpty) {
      print('DB Result: No user found for ID: $userId');
      return Response.notFound(json.encode({'message': 'User not found.'}));
    }

    final row = result.first.toColumnMap();

    // Check if user is a member of any team (to decide onboarding flow)
    final teamMemberRows = await _db.query(
      'SELECT 1 FROM team_members WHERE user_id = @userId::uuid LIMIT 1',
      substitutionValues: {'userId': userId},
    );
    final isMember = teamMemberRows.isNotEmpty;

    return Response.ok(json.encode({
      'name': row['name'],
      'email': row['email'],
      'profile_picture_base64': row['profile_picture_base64'],
      'has_completed_onboarding': row['has_completed_onboarding'],
      'invited': isMember,
    }), headers: {'Content-Type': 'application/json'});
  } catch (e, stackTrace) {
    print('Error retrieving profile: $e');
    print(stackTrace);
    return Response.internalServerError(body: 'An unexpected server error occurred.');
  }
}

// Handler to mark onboarding as completed for a user.
Future<Response> _completeOnboardingHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    await _db.query(
      'UPDATE users SET has_completed_onboarding = true WHERE id = @id',
      substitutionValues: {'id': userId},
    );

    return Response.ok(
      json.encode({'success': true, 'message': 'Onboarding marked as completed.'}),
      headers: {'Content-Type': 'application/json'},
    );
  } catch (e, stackTrace) {
    print('Error completing onboarding: $e');
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

// Add the missing `has_completed_onboarding` column to the `users` table if it doesn't exist.
Future<void> _ensureOnboardingColumn() async {
  try {
    await _db.query(r"""
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='users' AND column_name='has_completed_onboarding') THEN
          ALTER TABLE users ADD COLUMN has_completed_onboarding BOOLEAN DEFAULT FALSE NOT NULL;
        END IF;
      END
      $$;
    """);
    print('Ensured `has_completed_onboarding` column exists in `users` table.');
  } catch (e, st) {
    print('Failed to ensure onboarding column: $e');
    print(st);
    rethrow;
  }
}

Future<void> _ensureNotesTable() async {
  try {
    await _db.query(r"""
      CREATE TABLE IF NOT EXISTS public.notes (
          id uuid DEFAULT public.uuid_generate_v4() PRIMARY KEY,
          user_id uuid NOT NULL,
          type character varying(20) DEFAULT 'text' NOT NULL,
          content text,
          media_url text, -- Keep for backwards compatibility or optional file storage
          media_base64 text, -- For storing data directly as base64
          created_at timestamp with time zone DEFAULT now() NOT NULL
      );
    """);
    // Ensure media_base64 column exists if table was already created
    await _db.query(r"""
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='notes' AND column_name='media_base64') THEN
          ALTER TABLE notes ADD COLUMN media_base64 TEXT;
        END IF;
      END
      $$;
    """);
    print('Ensured `notes` table exists and has media_base64.');
  } catch (e, st) {
    print('Failed to ensure notes table: $e');
    print(st);
    rethrow;
  }
}

Future<void> _ensureCommentsTable() async {
  try {
    await _db.query(r"""
      CREATE TABLE IF NOT EXISTS public.comments (
          id uuid DEFAULT public.uuid_generate_v4() PRIMARY KEY,
          todo_id uuid NOT NULL,
          user_id uuid NOT NULL,
          text text NOT NULL,
          created_at timestamp with time zone DEFAULT now() NOT NULL
      );
    """);
    print('Ensured `comments` table exists.');
  } catch (e, st) {
    print('Failed to ensure comments table: $e');
    print(st);
    rethrow;
  }
}

Future<void> _ensureSubTodosTable() async {
  try {
    await _db.query(r"""
      CREATE TABLE IF NOT EXISTS public.sub_todos (
          id uuid DEFAULT public.uuid_generate_v4() PRIMARY KEY,
          todo_id uuid NOT NULL,
          title text NOT NULL,
          description text,
          due_date date,
          due_time time without time zone,
          priority integer,
          label_id uuid,
          is_completed boolean DEFAULT false NOT NULL,
          created_at timestamp with time zone DEFAULT now() NOT NULL
      );
    """);

    // Add missing columns if table already existed
    await _db.query(r"""
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sub_todos' AND column_name='description') THEN
          ALTER TABLE sub_todos ADD COLUMN description TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sub_todos' AND column_name='due_date') THEN
          ALTER TABLE sub_todos ADD COLUMN due_date DATE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sub_todos' AND column_name='due_time') THEN
          ALTER TABLE sub_todos ADD COLUMN due_time TIME WITHOUT TIME ZONE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sub_todos' AND column_name='priority') THEN
          ALTER TABLE sub_todos ADD COLUMN priority INTEGER;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sub_todos' AND column_name='label_id') THEN
          ALTER TABLE sub_todos ADD COLUMN label_id UUID;
        END IF;
      END
      $$;
    """);
    print('Ensured `sub_todos` table and columns exist.');
  } catch (e, st) {
    print('Failed to ensure sub_todos table: $e');
    print(st);
    rethrow;
  }
}

Future<Response> _addSubTodoHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final body = json.decode(await request.readAsString()) as Map<String, dynamic>;
    final todoId = body['todo_id'] as String?;
    final title = body['title'] as String?;
    final description = body['description'] as String?;
    final dueDate = body['due_date'] as String?;
    final dueTime = body['due_time'] as String?;
    final priority = body['priority'] as int?;
    final labelId = body['label_id'] as String?;

    if (todoId == null || title == null || title.trim().isEmpty) {
      return Response(400, body: json.encode({'message': 'todo_id and title are required.'}));
    }

    await _db.query(r"""
      INSERT INTO sub_todos (todo_id, title, description, due_date, due_time, priority, label_id)
      VALUES (@todoId::uuid, @title, @description, @dueDate, @dueTime, @priority, @labelId::uuid)
    """, substitutionValues: {
      'todoId': todoId,
      'title': title,
      'description': description,
      'dueDate': dueDate,
      'dueTime': dueTime,
      'priority': priority,
      'labelId': labelId,
    });

    return Response.ok(json.encode({'success': true, 'message': 'Sub-to do added.'}));
  } catch (e, st) {
    print('Error in _addSubTodoHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

Future<Response> _getSubTodosHandler(Request request, String todoId) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final rows = await _db.query(r"""
      SELECT st.id, st.title, st.description, st.due_date, st.due_time, st.priority, st.label_id, st.is_completed, st.created_at, l.name as label_name, l.color as label_color
      FROM sub_todos st
      LEFT JOIN labels l ON l.id = st.label_id
      WHERE st.todo_id = @todoId::uuid
      ORDER BY st.created_at ASC
    """, substitutionValues: {'todoId': todoId});

    final subTodos = rows.map((r) {
      // Manually build map to avoid JSArray issues with toColumnMap in some environments
      final Map<String, dynamic> m = {};
      for (var i = 0; i < rows.columnDescriptions.length; i++) {
        m[rows.columnDescriptions[i].columnName] = r[i];
      }
      
      if (m['created_at'] is DateTime) m['created_at'] = (m['created_at'] as DateTime).toIso8601String();
      if (m['due_date'] is DateTime) {
        final dt = m['due_date'] as DateTime;
        m['due_date'] = "${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')}";
      }
      // Ensure UUIDs and other fields are strings, not objects or lists
      m['id'] = m['id']?.toString();
      m['todo_id'] = m['todo_id']?.toString();
      m['label_id'] = m['label_id']?.toString();
      
      return m;
    }).toList();

    return Response.ok(json.encode(subTodos), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getSubTodosHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

Future<Response> _toggleSubTodoHandler(Request request, String id) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final body = json.decode(await request.readAsString()) as Map<String, dynamic>;
    final isCompleted = body['is_completed'] as bool?;

    if (isCompleted == null) {
      return Response(400, body: json.encode({'message': 'is_completed is required.'}));
    }

    await _db.query(r"""
      UPDATE sub_todos
      SET is_completed = @isCompleted
      WHERE id = @id::uuid
    """, substitutionValues: {'id': id, 'isCompleted': isCompleted});

    return Response.ok(json.encode({'success': true, 'message': 'Sub-to do updated.'}));
  } catch (e, st) {
    print('Error in _toggleSubTodoHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

Future<Response> _updateSubTodoHandler(Request request, String id) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final body = json.decode(await request.readAsString()) as Map<String, dynamic>;
    
    final updates = <String, dynamic>{};
    final List<String> setClauses = [];

    if (body.containsKey('title')) {
      updates['title'] = body['title'];
      setClauses.add('title = @title');
    }
    if (body.containsKey('description')) {
      updates['description'] = body['description'];
      setClauses.add('description = @description');
    }
    if (body.containsKey('due_date')) {
      updates['dueDate'] = body['due_date'];
      setClauses.add('due_date = @dueDate');
    }
    if (body.containsKey('due_time')) {
      updates['dueTime'] = body['due_time'];
      setClauses.add('due_time = @dueTime');
    }
    if (body.containsKey('priority')) {
      updates['priority'] = body['priority'];
      setClauses.add('priority = @priority');
    }
    if (body.containsKey('label_id')) {
      updates['labelId'] = body['label_id'];
      setClauses.add('label_id = @labelId::uuid');
    }

    if (setClauses.isEmpty) {
       return Response.ok(json.encode({'success': true, 'message': 'No changes made.'}));
    }

    updates['id'] = id;
    final query = 'UPDATE sub_todos SET ${setClauses.join(', ')} WHERE id = @id::uuid';
    
    await _db.query(query, substitutionValues: updates);

    return Response.ok(json.encode({'success': true, 'message': 'Sub-to do updated.'}));
  } catch (e, st) {
    print('Error in _updateSubTodoHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

Future<Response> _addCommentHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final body = json.decode(await request.readAsString()) as Map<String, dynamic>;
    final todoId = body['todo_id'] as String?;
    final text = body['text'] as String?;

    if (todoId == null || text == null || text.trim().isEmpty) {
      return Response(400, body: json.encode({'message': 'todo_id and text are required.'}));
    }

    await _db.query(r"""
      INSERT INTO comments (todo_id, user_id, text)
      VALUES (@todoId::uuid, @userId::uuid, @text)
    """, substitutionValues: {'todoId': todoId, 'userId': userId, 'text': text});

    return Response.ok(json.encode({'success': true, 'message': 'Comment added.'}));
  } catch (e, st) {
    print('Error in _addCommentHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

Future<Response> _getCommentsHandler(Request request, String todoId) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final rows = await _db.query(r"""
      SELECT c.id, c.text, c.created_at, u.name as author_name, u.profile_picture_base64
      FROM comments c
      JOIN users u ON u.id = c.user_id
      WHERE c.todo_id = @todoId::uuid
      ORDER BY c.created_at ASC
    """, substitutionValues: {'todoId': todoId});

    final comments = rows.map((r) {
      final m = r.toColumnMap();
      if (m['created_at'] is DateTime) m['created_at'] = (m['created_at'] as DateTime).toIso8601String();
      return m;
    }).toList();

    return Response.ok(json.encode(comments), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getCommentsHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
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

Future<void> _initializeUserData(String userId) async {
  await _db.transaction((tx) async {
    // Check and set default filters
    final existingFilters = await tx.query('SELECT 1 FROM filters WHERE user_id = @userId::uuid LIMIT 1', substitutionValues: {'userId': userId});
    if (existingFilters.isEmpty) {
      await tx.query(r"""
        INSERT INTO filters (user_id, name, query, color, is_favorite, description)
        VALUES
          (@userId::uuid, 'Today', 'due_today', '#3D4CD6', true, 'Tasks due today'),
          (@userId::uuid, 'Overdue', 'overdue', '#EF4444', false, 'Past due tasks'),
          (@userId::uuid, 'This Week', 'this_week', '#F59E0B', false, 'Due in the next 7 days'),
          (@userId::uuid, 'High Priority', 'high_priority', '#D32F2F', false, 'Urgent & important tasks'),
          (@userId::uuid, 'Low Priority', 'low_priority', '#9E9E9E', false, 'Nice-to-have tasks'),
          (@userId::uuid, 'Completed', 'completed', '#2E7D32', true, 'Finished tasks'),
          (@userId::uuid, 'Assigned to Me', 'assigned_to_me', '#FF7043', false, 'Tasks assigned to you')
      """, substitutionValues: {'userId': userId});
    }

    // Check and set default labels (tags) -> Removed default label creation as per user request.
    // final existingLabels = await tx.query('SELECT 1 FROM labels WHERE user_id = @userId::uuid LIMIT 1', substitutionValues: {'userId': userId});
    // if (existingLabels.isEmpty) {
    //   await tx.query(r"""
    //     INSERT INTO labels (user_id, name, color, is_favorite)
    //     VALUES
    //       (@userId::uuid, 'Work', '#3D4CD6', false),
    //       (@userId::uuid, 'Personal', '#8E24AA', false),
    //       (@userId::uuid, 'Urgent', '#EF4444', false),
    //       (@userId::uuid, 'Meeting', '#0288D1', false),
    //       (@userId::uuid, 'Follow-up', '#F59E0B', false),
    //       (@userId::uuid, 'Finance', '#2E7D32', false),
    //       (@userId::uuid, 'Health', '#E91E63', false),
    //       (@userId::uuid, 'Learning', '#7C4DFF', false),
    //       (@userId::uuid, 'Shopping', '#FF7043', false),
    //       (@userId::uuid, 'Ideas', '#607D8B', false),
    //       (@userId::uuid, 'Default', '#9E9E9E', false)
    //   """, substitutionValues: {'userId': userId});
    // }
  });
}

// Ensure subscription tables exist and seed default plans.
Future<void> _ensureSubscriptionTables() async {
  try {
    await _db.query(r"""
      CREATE TABLE IF NOT EXISTS public.subscription_plans (
          id uuid DEFAULT public.uuid_generate_v4() PRIMARY KEY,
          name character varying(100) UNIQUE NOT NULL,
          member_limit integer NOT NULL,
          price numeric(10,2) NOT NULL,
          stripe_price_id character varying(255),
          created_at timestamp with time zone DEFAULT now() NOT NULL
      );
    """);

    await _db.query(r"""
      CREATE TABLE IF NOT EXISTS public.user_subscriptions (
          id uuid DEFAULT public.uuid_generate_v4() PRIMARY KEY,
          user_id uuid NOT NULL UNIQUE,
          plan_id uuid NOT NULL,
          stripe_customer_id character varying(255),
          stripe_subscription_id character varying(255),
          card_last_four character varying(4),
          card_brand character varying(50),
          status character varying(20) DEFAULT 'active' NOT NULL,
          created_at timestamp with time zone DEFAULT now() NOT NULL,
          FOREIGN KEY (user_id) REFERENCES public.users(id),
          FOREIGN KEY (plan_id) REFERENCES public.subscription_plans(id)
      );
    """);

    // Table to track trial usage by email to prevent abuse
    await _db.query(r"""
      CREATE TABLE IF NOT EXISTS public.trial_usage (
          email character varying(255) PRIMARY KEY,
          used_at timestamp with time zone DEFAULT now() NOT NULL
      );
    """);

    // Add stripe_price_id column if it doesn't exist
    await _db.query(r"""
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='subscription_plans' AND column_name='stripe_price_id') THEN
          ALTER TABLE subscription_plans ADD COLUMN stripe_price_id VARCHAR(255);
        END IF;
      END
      $$;
    """);

    // Seed default plans (User needs to fill in their own Stripe Price IDs later)
    final res = await _db.query('SELECT COUNT(*) FROM subscription_plans');
    final count = res.first[0] as int;
    if (count == 0) {
      await _db.query(r"""
        INSERT INTO subscription_plans (name, member_limit, price, stripe_price_id) VALUES
        ('Lite', 2, 5.00, 'placeholder'),
        ('Pro', 5, 10.00, 'placeholder'),
        ('Elite', 10, 15.00, 'placeholder')
      """);
      print('Seeded subscription plans: Lite, Pro, Elite.');
    }

    // Automatically sync these plans with Stripe to get real Price IDs
    await _syncPlansWithStripe();
  } catch (e, st) {
    print('Failed to ensure subscription tables: $e');
    print(st);
    rethrow;
  }
}

/// Automatically creates Products and Prices in Stripe for plans that don't have them.
Future<void> _syncPlansWithStripe() async {
  if (Config.stripeSecretKey.isEmpty) {
    print('Skipping Stripe plan sync: STRIPE_SECRET_KEY is not set.');
    return;
  }

  try {
    final rows = await _db.query('SELECT id, name, price, stripe_price_id FROM subscription_plans');
    for (final row in rows) {
      final planData = row.toColumnMap();
      final planId = planData['id'];
      final name = planData['name'] as String;
      final price = double.tryParse(planData['price'].toString()) ?? 0.0;
      final currentStripeId = planData['stripe_price_id'] as String?;

      if (currentStripeId == null || currentStripeId == 'placeholder' || currentStripeId.startsWith('price_')) {
        // Even if it starts with price_, we might want to verify or just skip.
        // For simplicity, let's only create if it's 'placeholder' or null.
        if (currentStripeId != null && currentStripeId != 'placeholder') continue;

        print('Creating Stripe product and price for plan: $name (\$${price})...');

        // 1. Create Product
        final prodResp = await http.post(
          Uri.parse('https://api.stripe.com/v1/products'),
          headers: {
            'Authorization': 'Bearer ${Config.stripeSecretKey}',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: {
            'name': 'Klarto $name Plan',
            'description': 'Subscription for Klarto $name plan with specific member limits.',
          },
        );

        if (prodResp.statusCode != 200) {
          print('Failed to create Stripe product for $name: ${prodResp.body}');
          continue;
        }
        final productId = json.decode(prodResp.body)['id'];

        // 2. Create Price
        final priceResp = await http.post(
          Uri.parse('https://api.stripe.com/v1/prices'),
          headers: {
            'Authorization': 'Bearer ${Config.stripeSecretKey}',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: {
            'unit_amount': (price * 100).toInt().toString(), // Stripe uses cents
            'currency': 'usd',
            'recurring[interval]': 'month',
            'product': productId,
          },
        );

        if (priceResp.statusCode != 200) {
          print('Failed to create Stripe price for $name: ${priceResp.body}');
          continue;
        }
        final stripePriceId = json.decode(priceResp.body)['id'];

        // 3. Update DB
        await _db.query('UPDATE subscription_plans SET stripe_price_id = @sid WHERE id = @id::uuid', 
          substitutionValues: {'sid': stripePriceId, 'id': planId});
        
        print('Successfully synced $name with Stripe. Price ID: $stripePriceId');
      }
    }
  } catch (e) {
    print('Error during Stripe plan sync: $e');
  }
}

// Returns list of available subscription plans.
Future<Response> _getPlansHandler(Request request) async {
  try {
    final rows = await _db.query('SELECT id, name, member_limit, price FROM subscription_plans ORDER BY price ASC');
    final plans = rows.map((r) => r.toColumnMap()).toList();
    return Response.ok(json.encode(plans), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getPlansHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

// Returns the current user's subscription details.
Future<Response> _getCurrentSubscriptionHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final rows = await _db.query(r"""
      SELECT us.id, us.status, us.card_last_four, us.card_brand, us.created_at, sp.name as plan_name, sp.member_limit, sp.price
      FROM user_subscriptions us
      JOIN subscription_plans sp ON us.plan_id = sp.id
      WHERE us.user_id = @userId::uuid
    """, substitutionValues: {'userId': userId});

    if (rows.isEmpty) {
      return Response.ok(json.encode(null), headers: {'Content-Type': 'application/json'});
    }

    final sub = rows.first.toColumnMap();
    if (sub['created_at'] is DateTime) sub['created_at'] = (sub['created_at'] as DateTime).toIso8601String();
    
    return Response.ok(json.encode(sub), headers: {'Content-Type': 'application/json'});
  } catch (e, st) {
    print('Error in _getCurrentSubscriptionHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error.'}));
  }
}

// Subscribes a user to a plan using Stripe.
Future<Response> _subscribeHandler(Request request) async {
  try {
    final userId = request.context['userId'] as String?;
    if (userId == null) return Response.forbidden('Not authorized.');

    final body = json.decode(await request.readAsString()) as Map<String, dynamic>;
    final planId = body['plan_id'] as String?;
    final paymentMethodId = body['payment_method_id'] as String?; // Stripe PaymentMethod ID from frontend
    final isTrial = body['is_trial'] == true;

    if (planId == null || paymentMethodId == null) {
      return Response(400, body: json.encode({'message': 'Plan ID and Payment Method ID are required.'}));
    }

    // 1. Get Plan Details (Stripe Price ID)
    final planRows = await _db.query('SELECT stripe_price_id, name, member_limit FROM subscription_plans WHERE id = @id::uuid', substitutionValues: {'id': planId});
    if (planRows.isEmpty) return Response(404, body: json.encode({'message': 'Plan not found.'}));
    final planData = planRows.first.toColumnMap();
    final stripePriceId = planData['stripe_price_id'] as String?;
    if (stripePriceId == null || stripePriceId.startsWith('price_placeholder') || stripePriceId.contains('placeholder')) {
       return Response(500, body: json.encode({'message': 'Server is not configured with a valid Stripe Price ID for this plan.'}));
    }

    // 2. Get User Email
    final userRows = await _db.query('SELECT email FROM users WHERE id = @id::uuid', substitutionValues: {'id': userId});
    final userEmail = userRows.first[0] as String;

    // --- Trail Abuse Prevention ---
    if (isTrial) {
      final trialUsed = await _db.query(
        'SELECT 1 FROM trial_usage WHERE LOWER(email) = LOWER(@email)',
        substitutionValues: {'email': userEmail},
      );
      if (trialUsed.isNotEmpty) {
        return Response(403, body: json.encode({
          'message': 'You have already used a trial period on this account or another account with this email.'
        }), headers: {'Content-Type': 'application/json'});
      }
    }
    // --- End Trail Abuse Prevention ---

    // 3. Create or Get Stripe Customer
    String? stripeCustomerId;
    final existingSub = await _db.query('SELECT stripe_customer_id FROM user_subscriptions WHERE user_id = @id::uuid', substitutionValues: {'id': userId});
    if (existingSub.isNotEmpty) {
      stripeCustomerId = existingSub.first[0] as String?;
    }

    if (stripeCustomerId == null) {
      // Create Customer in Stripe
      final custResp = await http.post(
        Uri.parse('https://api.stripe.com/v1/customers'),
        headers: {
          'Authorization': 'Bearer ${Config.stripeSecretKey}',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: {
          'email': userEmail,
          'metadata[user_id]': userId,
        },
      );
      if (custResp.statusCode != 200) {
        print('Stripe Customer Error: ${custResp.body}');
        return Response.internalServerError(body: json.encode({'message': 'Failed to create Stripe customer.'}));
      }
      stripeCustomerId = json.decode(custResp.body)['id'];
    }

    // 4. Attach Payment Method to Customer
    final attachResp = await http.post(
      Uri.parse('https://api.stripe.com/v1/payment_methods/$paymentMethodId/attach'),
      headers: {
        'Authorization': 'Bearer ${Config.stripeSecretKey}',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: {'customer': stripeCustomerId!},
    );
    if (attachResp.statusCode != 200) {
       print('Stripe Attach PM Error: ${attachResp.body}');
       // Payment Method might already be attached or invalid
       // return Response.internalServerError(body: json.encode({'message': 'Failed to attach payment method.'}));
    }

    // 5. Update Customer Default Payment Method
    await http.post(
      Uri.parse('https://api.stripe.com/v1/customers/$stripeCustomerId'),
      headers: {
        'Authorization': 'Bearer ${Config.stripeSecretKey}',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: {
        'invoice_settings[default_payment_method]': paymentMethodId,
      },
    );

    // 6. Create Stripe Subscription
    final Map<String, String> subBody = {
      'customer': stripeCustomerId!,
      'items[0][price]': stripePriceId,
      'expand[]': 'latest_invoice.payment_intent',
    };

    if (isTrial) {
      subBody['trial_period_days'] = '7'; // 7-day trial as requested
    }

    final subResp = await http.post(
      Uri.parse('https://api.stripe.com/v1/subscriptions'),
      headers: {
        'Authorization': 'Bearer ${Config.stripeSecretKey}',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: subBody,
    );

    if (subResp.statusCode != 200) {
      print('Stripe Subscription Error: ${subResp.body}');
      return Response.internalServerError(body: json.encode({'message': 'Failed to create Stripe subscription.'}));
    }

    final subData = json.decode(subResp.body);
    final stripeSubscriptionId = subData['id'];

    // 7. Record trial usage if applicable
    if (isTrial) {
      await _db.query(
        'INSERT INTO trial_usage (email) VALUES (LOWER(@email)) ON CONFLICT (email) DO NOTHING',
        substitutionValues: {'email': userEmail},
      );
    }

    // 8. Get Card Info for Display
    final pmResp = await http.get(
      Uri.parse('https://api.stripe.com/v1/payment_methods/$paymentMethodId'),
      headers: {'Authorization': 'Bearer ${Config.stripeSecretKey}'},
    );
    String lastFour = '****';
    String brand = 'Card';
    if (pmResp.statusCode == 200) {
      final pmData = json.decode(pmResp.body);
      lastFour = pmData['card']['last4']?.toString() ?? '****';
      brand = pmData['card']['brand']?.toString() ?? 'Card';
    }

    // 8. Update DB
    await _db.query(r"""
      INSERT INTO user_subscriptions (user_id, plan_id, stripe_customer_id, stripe_subscription_id, card_last_four, card_brand, status)
      VALUES (@userId::uuid, @planId::uuid, @custId, @subId, @lastFour, @brand, 'active')
      ON CONFLICT (user_id) DO UPDATE SET
        plan_id = EXCLUDED.plan_id,
        stripe_customer_id = EXCLUDED.stripe_customer_id,
        stripe_subscription_id = EXCLUDED.stripe_subscription_id,
        card_last_four = EXCLUDED.card_last_four,
        card_brand = EXCLUDED.card_brand,
        status = 'active',
        created_at = now()
    """, substitutionValues: {
      'userId': userId,
      'planId': planId,
      'custId': stripeCustomerId,
      'subId': stripeSubscriptionId,
      'lastFour': lastFour,
      'brand': brand,
    });

    return Response.ok(json.encode({'success': true, 'message': 'Subscribed successfully.'}));
  } catch (e, st) {
    print('Error in _subscribeHandler: $e');
    print(st);
    return Response.internalServerError(body: json.encode({'message': 'Server error: $e'}));
  }
}
