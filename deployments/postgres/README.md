# PostgreSQL target store

`001_init.sql` is a target schema, not yet wired into the Go service. M9 should add migrations, a PostgreSQL implementation of `store.RunStore`, queue leases, integration tests with rollback, and a file-to-PostgreSQL import tool.

Do not run multiple API replicas against the current file store. The target transaction should update Run state and append its audit event atomically.
