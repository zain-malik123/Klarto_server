-- Migration 0005: create todos and labels mapping tables
BEGIN;

-- Labels need to exist before todos because todos references labels
CREATE TABLE IF NOT EXISTS labels (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  color text,
  user_id uuid,
  team_id uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS todos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  title text NOT NULL,
  description text,
  project_name text,
  project_id uuid,
  team_id uuid,
  due_date timestamptz,
  due_time text,
  repeat_value text,
  priority integer DEFAULT 0,
  is_completed boolean NOT NULL DEFAULT false,
  label_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_todos_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_todos_team FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE SET NULL,
  CONSTRAINT fk_todos_label FOREIGN KEY(label_id) REFERENCES labels(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_todos_user_id ON todos(user_id);
CREATE INDEX IF NOT EXISTS idx_todos_team_id ON todos(team_id);
CREATE INDEX IF NOT EXISTS idx_todos_project_id ON todos(project_id);
CREATE INDEX IF NOT EXISTS idx_todos_due_date ON todos(due_date);

CREATE TABLE IF NOT EXISTS todo_labels (
  todo_id uuid NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
  label_id uuid NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
  PRIMARY KEY (todo_id, label_id)
);

COMMIT;
