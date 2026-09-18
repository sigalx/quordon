module github.com/sigalx/quordon

go 1.26.0

require (
	github.com/go-sql-driver/mysql v1.10.0
	github.com/pb33f/libopenapi v0.38.6
	github.com/pb33f/libopenapi-validator v0.14.0
	golang.org/x/crypto v0.55.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/basgys/goxml2json v1.1.1-0.20231018121955-e66ee54ceaad // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/go-openapi/jsonpointer v0.23.2 // indirect
	github.com/go-openapi/swag/jsonname v0.26.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pb33f/jsonpath v0.8.2 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.6 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace github.com/go-sql-driver/mysql => ./third_party/go-sql-driver/mysql

replace gopkg.in/yaml.v3 => ./third_party/go-yaml
