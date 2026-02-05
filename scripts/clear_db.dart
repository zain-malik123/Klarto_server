import 'package:postgres/postgres.dart';
import '../lib/config.dart';

void main() async {
  Config.load();

  final connection = PostgreSQLConnection(
    Config.dbHost,
    Config.dbPort,
    Config.dbName,
    username: Config.dbUser,
    password: Config.dbPassword,
  );

  try {
    print('Connecting to database ${Config.dbName} on ${Config.dbHost}...');
    await connection.open();

    print('Clearing all tables...');

    // We use CASCADE to ensure that dependent rows are also removed.
    // The order doesn't strictly matter with CASCADE, but we list user-data tables first.
    await connection.query('''
      TRUNCATE TABLE 
        activities, 
        comments, 
        filters, 
        invitations, 
        labels, 
        notes, 
        projects, 
        sub_todos, 
        team_members, 
        teams, 
        todo_labels, 
        todos, 
        user_subscriptions, 
        subscription_plans,
        users 
      RESTART IDENTITY CASCADE;
    ''');

    print('Successfully cleared all data from the database.');
  } catch (e) {
    print('Error clearing database: $e');
  } finally {
    await connection.close();
  }
}
