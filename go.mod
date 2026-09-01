module github.com/jamesread/armature-iam

go 1.25.5

require (
	connectrpc.com/authn v0.2.0
	github.com/alexedwards/argon2id v1.0.0
	github.com/jamesread/httpauthshim v0.1.0
	github.com/mattn/go-sqlite3 v1.14.50
	github.com/sirupsen/logrus v1.10.2
	github.com/stretchr/testify v1.12.1
)

require (
	connectrpc.com/connect v1.20.0 // indirect
	github.com/MicahParks/jwkset v0.11.0 // indirect
	github.com/MicahParks/keyfunc/v3 v3.7.0 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/jamesread/httpauthshim => ../httpauthshim
