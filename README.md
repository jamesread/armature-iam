<div align = "center">
  <img alt = "project logo" src = "logo.svg" width = "128" />
  <h1>armature-iam</h1>

  Database users, group RBAC, and Connect auth middleware for SOA apps, on top of httpauthshim.

  [![Maturity Badge](https://img.shields.io/badge/maturity-alpha-red.svg)](#none)
  [![Discord](https://img.shields.io/discord/846737624960860180?label=Discord%20Server)](https://discord.gg/jhYWWpNJ3v)
  [![Go Report Card](https://goreportcard.com/badge/github.com/jamesread/armature-iam)](https://goreportcard.com/report/github.com/jamesread/armature-iam)

</div>

armature-iam is the identity *account* layer for jwr SOA apps. [httpauthshim](https://github.com/jamesread/httpauthshim) answers **who is this HTTP request**. This library maps that username onto `user_accounts`, loads group-based RBAC, and wraps Connect RPC / MCP handlers.

Apps keep their own IAM admin RPCs and protobuf. This module does not ship a Connect service.

## Packages

| Package | Role |
|---------|------|
| `store` | Types and `Store` interface |
| `store/sqlite` | SQLite implementation on `*sql.DB` |
| `rbac` | `EffectiveRBAC` and core permission / system names |
| `password` | Argon2id hashing and prefixed API keys |
| `layer` | httpauthshim wiring, Connect `authn`, MCP Bearer wrap |
| `migrate/sqlite` | sql-migrate script to copy into the app |

## Usage

```go
iamDB := iamsqlite.New(db) // db is *sql.DB with schema applied
l, err := layer.New(iamDB, layer.Config{
    CookieName:            "app-sid",
    AuthYAML:              cfg.Auth,
    AllowUnauthenticated:  []string{loginProc, statusProc},
    RequiredPermission:    requiredPermission,
    APIKeyPrefix:          "app_",
})
path, h := apiv1connect.NewAppServiceHandler(svc)
h = l.WrapHandler(h)
```

The layer uses httpauthshim `sessions.NopPersistence` so apps that own DB cookies do not write YAML session files.

Copy `migrate/sqlite/3.iam.sql` into the app's sqlite migrations tree. The library does not run migrations.

Until a tagged httpauthshim release includes `NopPersistence`, `ConfigFromMap`, and `providers/hascallback`, develop with a sibling checkout:

```
Development/httpauthshim
Development/armature-iam
```

`go.mod` has `replace github.com/jamesread/httpauthshim => ../httpauthshim`.

## Development

```bash
make test
make gocyclo
make golangci
```
