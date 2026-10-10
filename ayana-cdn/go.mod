module ayanacdn

go 1.26.0

// The only direct dependency is golang.org/x/crypto (acme/autocert); the rest
// is the standard library. go.sum is created by `go mod tidy`, which the
// installer runs, so every module is verified against sum.golang.org on your
// server rather than trusted from this archive.
require golang.org/x/crypto v0.57.0

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
