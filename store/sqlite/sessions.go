package sqlite

import (
	"context"
	"fmt"

	"github.com/jamesread/armature-iam/store"
)

func (s *SQLite) CreateSession(ctx context.Context, sid string, userID int, impersonatorID *int) error {
	var impersonator any
	if impersonatorID != nil {
		impersonator = *impersonatorID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (sid, user_account_id, impersonator_user_id) VALUES (?, ?, ?)`,
		sid, userID, impersonator,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *SQLite) GetSessionBySID(ctx context.Context, sid string) (*store.SessionRow, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx, sessionSelectSQL()+` WHERE sid = ?`, sid))
	if err != nil {
		return nil, ignoreNoRows(fmt.Errorf("get session by sid: %w", err))
	}
	return sess, nil
}

func (s *SQLite) DeleteSession(ctx context.Context, sid string) error {
	return s.execOp(ctx, "delete session", `DELETE FROM sessions WHERE sid = ?`, sid)
}

func (s *SQLite) DeleteSessionsForUser(ctx context.Context, userID int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_account_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("delete sessions for user: %w", err)
	}
	return nil
}
