module github.com/clearcompass-ai/ortholog-operator

go 1.22

require (
	github.com/clearcompass-ai/ortholog-sdk v0.1.0
	github.com/jackc/pgx/v5 v5.7.4
)

// Development: SDK from local workspace. Remove for release.
replace github.com/clearcompass-ai/ortholog-sdk => ../ortholog-sdk
