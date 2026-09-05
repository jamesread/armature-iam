package store

const (
	UserCreatedByAdmin = "admin-created"
	UserCreatedBySSO   = "sso-autocreated"
)

type UserAccountRow struct {
	Username     string
	PasswordHash string
	CreatedBy    string
	CreatedAt    string
	UpdatedAt    string
	ID           int
}

type SessionRow struct {
	SID                string
	ImpersonatorUserID *int
	CreatedAt          string
	UpdatedAt          string
	ID                 int
	UserAccountID      int
}

type APIKeyRow struct {
	Name          string
	KeyValue      string
	LastUsedAt    string
	CreatedAt     string
	UpdatedAt     string
	ID            int
	UserAccountID int
	ReadOnly      bool
}

type UserGroupRow struct {
	Name        string
	CreatedAt   string
	UpdatedAt   string
	ID          int
	MemberCount int
}

type RBACPermissionRow struct {
	Name        string
	Description string
	ID          int
}

type RBACRoleRow struct {
	Name          string
	Description   string
	PermissionIDs []int
	ID            int
	GroupCount    int
	UserCount     int
}

type MyPermissionAuditRow struct {
	Permission     string
	GrantingGroups []string
	Granted        bool
}
