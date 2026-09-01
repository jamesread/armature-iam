package sqlite

import "embed"

// FS contains the sql-migrate IAM schema for apps to copy or apply.
//
//go:embed 3.iam.sql
var FS embed.FS
