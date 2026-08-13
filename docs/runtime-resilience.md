# Runtime resilience and adapter lifecycle

Orynelo treats the diagnostic engine as the mandatory core. Configuration
files, JSON logging, and SQLite history/profile storage are optional adapters.
A failure in any optional adapter is exposed as a stable startup warning while
diagnostics continue with default in-memory configuration and a discard
logger.

## Persistence policies

- `default` attempts configuration, logging, and SQLite. Each unavailable
  adapter degrades independently.
- `no-history` never opens SQLite; configuration and logging remain enabled.
- `ephemeral` does not resolve application paths and creates no directories,
  configuration, log, database, backup, or checksum files.

The CLI selects the policy with `--persistence`. The desktop interface shows a
limited-local-state dialog whenever the default startup degrades. History and
profile operations are unavailable in that state, but diagnosis and report
generation remain available.

## History authority and migration recovery

History uses an explicit hybrid contract. Normalized SQLite tables are
authoritative for list queries, filters, sorting, retention, and deletion. The
versioned JSON snapshot is authoritative for reconstructing the complete
diagnosis. Both representations are written in one transaction. Every released
database schema and snapshot schema has a compatibility fixture in
`internal/storage/testdata`.

Before upgrading a non-empty database, Orynelo runs `PRAGMA quick_check` and
creates a consistent online backup with `VACUUM INTO`. The backup is private
and accompanied by a SHA-256 manifest. All pending schema steps then run in one
transaction, so a failed chain rolls back without partially advancing the
original database. Integrity and migration errors advertise three
non-destructive recovery modes: read-only inspection, quarantine, or a run
without storage. Bootstrap currently chooses the last mode and keeps the
verified backup available for manual recovery.

## Adapter and event delivery contract

Application adapters receive the caller context with a maximum cooperative
timeout of five seconds. Adapter and event-consumer panics are recovered and
reported as typed internal errors. Diagnostic events pass through a bounded
queue; a stalled consumer cannot block the engine. Dropped events, consumer
panics, and an incomplete drain are recorded in `Diagnosis.eventDelivery`,
and overflow is also emitted as a best-effort `delivery_overflow` event.

Go cannot forcibly stop a goroutine blocked in an operating-system call that
ignores context. On the CLI and desktop entry points, the first SIGINT/SIGTERM
cancels cooperatively and a second signal exits immediately. Closing the GUI
first cancels all task scopes; a second close forces the Fyne application to
quit. After the window closes, Orynelo waits at most two seconds for
non-cooperative tasks.
