# Example Dataset

## Purpose

Provide a documented, repeatable way to load a Sentinel backend with a
fictional dataset, so that Sentinel and the web UI developed in the separate
`sentinel-aura` repository (`docs/architecture.md`, System Boundary) can be
developed, tested end to end, and shown in screenshots without real data and
without access to any external data source.

The `sentinel example-data load` command loads the dataset. It is part of the
published image, so a backend started from any release that provides it can be
loaded with the dataset of that release (`docs/deployment.md`, Loading the
Example Dataset). The command runs Sentinel's own service operations: every
state, derived value, and audit event of the dataset arises as it would in
real use and follows the rules of the release that loads it.

The dataset is for local development and test environments only. It MUST NOT
be loaded into a staging or production database (Security Considerations).

## Scope

This specification defines the command, the rules of a load, the service that
performs it, and the content of the dataset.

Out of scope:

- historical timestamps: every persisted creation, update, and audit time is a
  time of the load (Time Base);
- fetcher run history, API keys, sessions, external users, and IBS track
  release checkpoints;
- loading into a database that holds data, and resetting or removing the
  dataset: a dataset backend is recreated from a new database;
- an API operation (No API Operation).

## Related Specifications

| Spec | Relationship |
|---|---|
| `docs/conventions.md` (CLI Conventions; Example Data in Documentation) | Output contract of the command; fictional-data rule that the dataset follows |
| `docs/features/platform/cli-infrastructure.md` | Shared CLI mechanism. Steps and Transactions below is an explicit exception to its one-transaction rule for mutating workflows |
| `docs/features/identity/user-service.md` | `create_user()` and `deactivate_user()` |
| `docs/features/platform/system-settings.md` | `update_default_cvss_version()` |
| `docs/features/platform/fetcher-infrastructure.md` (FetcherConfig) and `docs/features/platform/fetcher-operations.md` (`update_fetcher_config`) | Fetcher configuration bootstrap and disabling |
| `docs/features/packages/product-catalog.md` (Catalog Publication Boundaries) | Product, lifecycle, and threshold publication |
| `docs/features/tickets/cve-service.md` and `docs/features/tickets/ticket-references.md` | CVE ingestion and automatic references |
| `docs/features/tickets/ticket-service.md`, `docs/features/tickets/ticket-mutations.md`, and `docs/features/tickets/ticket-priority.md` | Ticket creation, assignment, ignore, duplicate, confidentiality, access grants, SUSE assessments, and priority override |
| `docs/features/packages/package-service.md` | Package records, track status, and Product release |
| `docs/features/packages/ibs-submission-tracking.md` (Trusted Observation Application) | IBS request evidence and delivery status |
| `docs/features/platform/testing-strategy.md` (Mandatory Test Scenarios → Example Dataset) | Load and coverage tests that keep the dataset aligned with Sentinel |
| `docs/deployment.md` (Loading the Example Dataset) | Operator procedure for the published image and a local checkout |

## Command

### `sentinel example-data load`

Loads the example dataset into a newly created database.

```
sentinel example-data load
```

**Parameters**: none.

**Prerequisites**: the database is newly created and migrated to the head
revision (`alembic upgrade head`), and no other Sentinel process has run
against it. PostgreSQL is reachable and the application settings are valid
(`docs/configuration.md`). The command uses no Redis, Celery broker, or
network access.

**Behavior**:

1. Delegates to `example_dataset.load_example_dataset()` (Service), which first
   applies the Empty-Database Guard. If the database is not empty, prints to
   stderr `Error: The database is not empty. The example dataset loads only
   into a newly created database.` and exits with code 1. Nothing is written.
2. Loads the dataset in the six steps of Steps and Transactions and reports
   each step on stdout with the fail-fast step report of `docs/conventions.md`
   (Multi-Step Reporting): `✓ {step}` after a step completes.
3. If a step fails, prints `✗ {step}: {reason}` for it and
   `— {step} not attempted (aborted due to previous error)` for each later
   step. `{reason}` is the message of a service exception, and otherwise the
   exception class name. When at least one operation was committed before the
   failure, it then prints to stderr `Warning: The database holds part of the
   example dataset. Recreate the database before loading it again.` The
   exception then reaches the shared exception mapper
   (`docs/features/platform/cli-infrastructure.md`, Error Handling & Exit Code
   Mapping), which prints `Error: {message}` and exits with code 1 for a
   service exception and with code 2 otherwise.
4. After the last step, prints `Loaded the example dataset.` to stdout and
   exits with code 0.

Example output of a successful load:

```
✓ Users
✓ System settings
✓ Fetchers
✓ Product catalog
✓ CVEs and tickets
✓ Ticket work
Loaded the example dataset.
```

**Idempotency**: Not idempotent (by design). A load changes an empty database
into a dataset backend; a repeated invocation fails the Empty-Database Guard
with exit code 1 and changes nothing. Recognizing a complete earlier load as an
already reached state would require persisted load state, which the dataset
does not need: a dataset backend is recreated, not reloaded.

**Exit codes**: 0 on success; 1 when the database is not empty or a service
exception fails a step; 2 when the database is unreachable, the settings are
invalid, or another exception fails a step; 130 and 143 on `SIGINT` and
`SIGTERM` (`docs/features/platform/cli-infrastructure.md`, Signal Handling).
An interrupted load leaves the operations committed before the interruption in
place, as a failed step does.

**Output channels**: the step report and the final confirmation on stdout;
the partial-dataset `Warning:` and every `Error:` message on stderr.

### No API Operation

The load has no API operation. It requires an empty database, in which no
user exists who could authenticate to call an endpoint: every mutation
endpoint other than sign-in requires an authenticated user, and sign-in
requires an existing user. Like the creation of the first
administrator (`docs/features/identity/user-management.md`, CLI Commands), it
is a bootstrap operation that requires shell access to the image. Every
operation that the dataset performs exists for consumers through its own API
operation or system process; the load adds no consumer capability.

## Loading Rules

### Empty-Database Guard

Before any write, the service reads whether any `User`, `Ticket`, `CVE`, or
`Product` row exists. The database is empty when none exists. Other tables are
not checked: the system-setting rows that the migrations seed and the fetcher
configuration rows that a process startup creates hold no domain data.

The guard protects a database that holds data from receiving the dataset and
its known credentials. It does not prove that the database is newly created:
the Ticket identifiers of the dataset (Tickets) are guaranteed only for a
newly created database, as Prerequisites requires.

### Steps and Transactions

A load runs these steps in this order:

| Step | Content |
|---|---|
| `Users` | Users |
| `System settings` | System Settings |
| `Fetchers` | Fetchers |
| `Product catalog` | Product Catalog |
| `CVEs and tickets` | CVEs, and the creation of every Ticket (Tickets) |
| `Ticket work` | The Ticket work of Tickets, Packages, Tracks, and Maintainers, IBS Requests, and References |

Each operation of a step — one call of a service function named in Dataset
Content, or for an ingestion its `upsert_cve()` call together with its
`upsert_references()` call (CVEs) — runs in its own session and transaction,
which the load commits before the next operation begins. The three catalog
publications commit their own transactions
(`docs/features/packages/product-catalog.md`, Catalog Publication
Boundaries). One transaction per operation is the granularity of the API
request or fetcher work unit that each operation stands for: each transaction
follows the ordinary lock order of its operation, and the operations receive
distinct, increasing timestamps. This is an explicit exception to the rule
that a mutating CLI workflow owns one transaction
(`docs/features/platform/cli-infrastructure.md`, Database Session
Management).

A failed or interrupted operation rolls back its own transaction. The
operations committed before it remain: once one has been committed, the
database holds part of the dataset and the Empty-Database Guard refuses
another load. Recovery is to recreate the database; the load provides no
resume or cleanup.

Concurrent loads into the same database are not supported. The first
operation of the `Users` step creates the same user in every load, so when two
loads pass the guard together, at most one proceeds past that operation; the
other fails at it with `UserConflictError` and has committed nothing.

### Attribution

The load performs no authentication and no capability check. It calls each
service in the way that the actor named in Dataset Content reaches it in real
use:

- A user-attributed operation passes the named dataset user as the acting
  user, with that user's consumer caller context: its identity and its
  effective scope (`docs/features/identity/rbac.md`). The user stands for the
  authenticated caller of the corresponding API operation and holds the
  capability that the operation requires (Predefined Roles). The services
  apply their own guards, including locked-current Ticket accessibility under
  that scope.
- A system operation passes no acting user and uses the service's system
  caller context. It stands for the system process that performs it in real
  use: CVE ingestion by the fetcher of the source that the data represents,
  Product catalog synchronization, IBS request reconciliation, and IBS track
  and Product release detection.
- The first administrator is created without an acting user, as the
  bootstrap command `sentinel manage-user create` creates it.

Every audit event therefore names the dataset user or the system actor of its
operation. Recording a dataset user as the actor of an operation that a CLI
process performs is the explicit exception to the actor rule of
`docs/features/platform/audit-trail-infrastructure.md` (Actor Field) for the
example dataset load.

The loader also stands in for the external sources and system processes of a
real installation. Where a specification names a source or process as the
origin of a fact or event — SMELT for package trees and maintainers, an
advisory in `updateinfo.xml` for a Product release, a fetcher for an external
identifier, or IBS for request evidence — a dataset backend holds the same
fact or event with fictional data from the loader.

### Isolation

A load performs no network I/O, uses no Redis or Celery broker, and runs no
post-commit effect:

- Every operation is a database operation of its service. Before committing an
  operation whose transaction it owns — every operation except the three
  catalog publications, which register none — the load verifies that the
  transaction registered no post-commit effect (`docs/conventions.md`,
  Caller-Owned Service Transactions), including no Ticket convergence effect
  (`docs/features/tickets/ticket-mutations.md`, Transaction-Local Ticket
  Convergence Registration). A registered effect is a defect of the dataset:
  the operation rolls back, discarding the effect, and the load raises
  `ExampleDatasetEffectError`, which fails the step.
- The dataset is built so that no operation registers one. Every fetcher is
  disabled before the first CVE or Ticket exists, so a manual creation with a
  CVE finds no eligible source for its freshness refresh
  (`docs/features/tickets/ticket-service.md`, create_ticket, step 11). No
  operation regresses a `Resolved` Ticket or exits the manual zone. Package
  records are created through `add_package_records()`, which registers no IBS
  request catch-up.
- The post-commit steps of the fetchers that own the catalog publications —
  Product catalog backfill and threshold eligibility recalculation — are not
  performed: no Ticket exists when the catalog is published.
- The RedBeat propagation that `update_fetcher_config()` returns is not
  applied. Celery Beat, started after the load, builds its schedule from
  PostgreSQL, where every fetcher is disabled
  (`docs/features/platform/fetcher-infrastructure.md`, Startup
  Reconciliation).
- The session-cache purge that follows `deactivate_user()`
  (`docs/features/identity/user-service.md`, `deactivate_user()`) is not
  performed: the deactivated dataset user has never signed in, so the
  deactivation invalidates no session and returns no session to purge.

The `Fetchers` step first creates the configuration of every fetcher in the
production fetcher registry, the registry that the API populates, through
`bootstrap_fetcher_configs()`. A fetcher that a later Sentinel version
registers is created enabled when the processes of that version start; each
version is therefore loaded into a new database.

### Time Base

The load captures its load instant `T`, in UTC, once before the guard, and its
load date `D`, the UTC calendar date of `T`. Every relative date and time in
Dataset Content is computed from them: `T − 3d` is three days before the load
instant, and `D + 365` is 365 days after the load date.

The persisted creation, update, and audit timestamps are the database times of
the operations, shortly after `T`; the load never backdates them. Remediation
deadlines, which derive from the Ticket creation time, therefore advance with
the age of the dataset (`docs/features/tickets/ticket-deadlines.md`). The
lifecycle dates of Product Catalog keep every listed lifecycle phase during
the first 180 days from `D`.

## Service

### `load_example_dataset()`

Module: `backend/app/services/example_dataset.py`. The dataset is static data
of this module, fixed for each release.

```python
async def load_example_dataset(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    progress: ExampleDatasetProgress | None = None,
) -> None:
```

The function is a service-owned orchestration boundary
(`docs/conventions.md`, Caller-Owned Service Transactions): it receives the
session factory, not a session, and opens one session for the guard and one
for each operation. `progress` receives the start and the completion of each
step, which the command turns into its step report; its concrete form is an
implementation choice.

**Q2 (guards)**: the Empty-Database Guard, before any write. A non-empty
database raises `ExampleDatasetNotEmptyError`.

**Q3 (behavior)**: captures `T` and `D`, applies the guard, imports the
production fetcher registry, then performs the steps of Steps and Transactions
with the operations, attribution, and values of Dataset Content, under
Isolation. A failure stops the load at the failing operation.

**Q4 (audit events)**: none of its own. The delegated services create the
events that Audit Trails summarizes.

**Q5 (re-invocation)**: not idempotent; after a load that committed at least
one operation, a repeated invocation raises `ExampleDatasetNotEmptyError` and
writes nothing.

**Q6 (exceptions)**: `ExampleDatasetNotEmptyError` and
`ExampleDatasetEffectError`; every exception of a delegated service and every
database exception propagate unchanged.

### Service Exceptions

`ExampleDatasetServiceError` inherits from `ServiceError`, and every
module-owned exception inherits from it. No exception of this module reaches
an API handler.

| Exception | Raised when | Handling |
|---|---|---|
| `ExampleDatasetNotEmptyError` | The database is not empty (Empty-Database Guard) | The command prints its guard error and exits with code 1 |
| `ExampleDatasetEffectError` | An operation of the load registered a post-commit effect | The operation has rolled back; the command reports the failed step, prints `Error: An operation of the example dataset registered a post-commit effect.`, and exits with code 1 |

## Dataset Content

Every personal, CVE, product, package, track, request, incident, advisory, and
reference identifier of the dataset is fictional
(`docs/conventions.md`, Example Data in Documentation), within the formats
that Sentinel enforces. Email addresses and URLs use the `example.com` domain,
which RFC 2606 reserves. An optional input or payload field that this section
does not give a value is omitted, so the service applies its default.

### Credentials

Every dataset user has the local password `example-dataset-password`. The
password is fixed, public, and the same in every release, so that a developer
and an automated test can sign in through local authentication
(`docs/features/identity/local-authentication.md`). SSO is not available on a
dataset backend: it matches only external users
(`docs/features/identity/sso-authentication.md`, Identity Mapping), and every
dataset user is a local user.

### Users

| Username | Full name | Email | Roles | Active |
|---|---|---|---|---|
| `jdoe` | John Doe | `john.doe@example.com` | `admin` | Yes |
| `asmith` | Alice Smith | `alice.smith@example.com` | `vulnerability_analyst` | Yes |
| `bwilson` | Bob Wilson | `bob.wilson@example.com` | `vulnerability_analyst` | Yes |
| `cwhite` | Carol White | `carol.white@example.com` | `restricted_analyst` | Yes |
| `dbrown` | Dave Brown | `dave.brown@example.com` | none | Yes |
| `eblack` | Eve Black | `eve.black@example.com` | `vulnerability_analyst` | No |

Operations of the `Users` step, in this order:

1. `create_user()` for `jdoe`, without an acting user.
2. `create_user()` for `asmith`, `bwilson`, `cwhite`, `dbrown`, and `eblack`,
   in this order, by `jdoe`. Every role has the `_manual` origin.
3. `deactivate_user()` for `eblack` by `jdoe`, with the reason
   `example dataset`.

`dbrown` holds no role: a user without roles who maintains packages
(Packages, Tracks, and Maintainers).

### System Settings

Operations of the `System settings` step: `update_default_cvss_version()` by
`jdoe`, first from `3.1` to `4.0`, then from `4.0` back to `3.1`. The dataset
therefore uses the default version `3.1` and records two setting changes. No
CVE exists yet, so the changes need no recalculation.

### Fetchers

Operations of the `Fetchers` step:

1. `bootstrap_fetcher_configs()` (Isolation).
2. `update_fetcher_config()` with `enabled = false` by `jdoe`, for every
   registered fetcher, in ascending order of fetcher name.

Every fetcher is disabled after the load.

### Product Catalog

| CPE | Name | Version | Display name | Repository | Lifecycle dates | Phase | CVSS threshold |
|---|---|---|---|---|---|---|---|
| `cpe:/o:example:fles:16.0` | `FLES` | `16.0` | Fictional Linux Enterprise Server 16.0 | `SUSE:Updates:FLES:16.0:x86_64` | FCS `D − 365`, GS end `D + 1825` | `general_support` | none |
| `cpe:/o:example:fles:15:sp7` | `FLES` | `15-SP7` | Fictional Linux Enterprise Server 15 SP7 | `SUSE:Updates:FLES:15-SP7:x86_64` | FCS `D − 730`, GS end `D + 365` | `general_support` | none |
| `cpe:/o:example:fles-ltss:15:sp5` | `FLES-LTSS` | `15-SP5` | Fictional Linux Enterprise Server LTSS 15 SP5 | `SUSE:Updates:FLES-LTSS:15-SP5:x86_64` | FCS `D − 1460`, GS end `D − 365`, ES end `D + 730` | `extended_support` | `7.0` |
| `cpe:/o:example:fles-ltss:15:sp4` | `FLES-LTSS` | `15-SP4` | Fictional Linux Enterprise Server LTSS 15 SP4 | `SUSE:Updates:FLES-LTSS:15-SP4:x86_64` | FCS `D − 1825`, GS end `D − 730`, ES end `D − 30`, RS end `D + 365` | `reactive_support` | none |
| `cpe:/o:example:fles:15:sp3` | `FLES` | `15-SP3` | Fictional Linux Enterprise Server 15 SP3 | `SUSE:Updates:FLES:15-SP3:x86_64` | FCS `D − 2555`, GS end `D − 1460`, ES end `D − 365` | `eol` | none |
| `cpe:/o:example:fles:17.0` | `FLES` | `17.0` | Fictional Linux Enterprise Server 17.0 | `SUSE:Updates:FLES:17.0:x86_64` | FCS `D + 180`, GS end `D + 2000` | `pre_release` | none |
| `cpe:/o:example:fles-micro:6.2` | `FLES-Micro` | `6.2` | Fictional Linux Enterprise Micro 6.2 | `SUSE:Updates:FLES-Micro:6.2:x86_64` | none | unavailable | none |

FCS is the first customer shipment, GS the General Support, ES the Extended
Support, and RS the Reactive Support of
`docs/features/packages/product-catalog.md` (Product Lifecycle Phases).

Operations of the `Product catalog` step, each a system operation that stands
for its synchronization fetcher:

1. Product publication of the seven Products, each with its one repository,
   as one snapshot at `T`.
2. Lifecycle publication of the dates above for the six Products that have
   them.
3. Threshold publication of the one threshold above.

The rest of this document names each Product by its display name without the
`Fictional Linux Enterprise` prefix, for example `Server 15 SP7`.

### CVEs

Every CVE is first ingested from the source in the "First" column, which
creates its Ticket (`docs/features/tickets/tickets.md`, Automatic: CVE
Ingestion), except the three CVEs created by a manual Ticket creation
(Tickets). An NVD ingestion supplies the description `Fictional vulnerability
{CVE ID} of the Sentinel example dataset.`, the state `PUBLISHED`, the
published date `T − n` days, where `n` is the number that ends the CVE ID
(`7` for `CVE-2099-0007`), the modified date `T − 1d`, the CVSS vector of the
table with provider `NVD`, and the CWE of the table with source `NVD`. A MITRE ingestion supplies the same description and
published date, the title `Fictional flaw {CVE ID}`, the state `PUBLISHED`
unless the table states otherwise, and the further data of the table. A KEV,
EPSS, or GHSA ingestion supplies only the data of the table.

| CVE | First | NVD CVSS vector | Severity | CWE | Further ingestions |
|---|---|---|---|---|---|
| `CVE-2099-0001` | NVD | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | critical | `CWE-787` | KEV: added `D − 2`. EPSS: score `0.94`, percentile `0.99`, assessed `D − 1` |
| `CVE-2099-0002` | NVD | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | high | `CWE-79` | EPSS: score `0.12`, percentile `0.85`, assessed `D − 1` |
| `CVE-2099-0003` | NVD | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | medium | `CWE-200` | — |
| `CVE-2099-0004` | NVD | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | low | — | — |
| `CVE-2099-0005` | NVD | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | none | — | — |
| `CVE-2099-0006` | MITRE | — | unresolved | — | — (no source supplies CVSS data) |
| `CVE-2099-0007` | NVD | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | critical | — | — |
| `CVE-2099-0008` | MITRE | — | unresolved | — | The first ingestion supplies the state `REJECTED`, rejected at `T − 2d` |
| `CVE-2099-0009` | NVD | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | high | `CWE-22` | MITRE: title, and one `cna` affected-version scope: vendor `Example`, product `fictional-tar`, versions from `1.0` up to but excluding `1.5` affected |
| `CVE-2099-0010` | NVD | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | medium | — | MITRE: title, and SSVC exploitation `poc`, automatable `no`, technical impact `partial`, version `2.0.3`, assessed `T − 3d`. GHSA: external identifier `GHSA-2c4f-7h9j-mqrv`. EPSS: score `0.02`, percentile `0.40`, assessed `D − 1` |
| `CVE-2099-0011` | NVD | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | high | `CWE-416` | — |
| `CVE-2099-0012` | NVD | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | high | — | — |
| `CVE-2099-0013` | NVD | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | high | `CWE-400` | — |
| `CVE-2099-0014` | NVD | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | high | `CWE-787` | — |
| `CVE-2099-0015` | NVD | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | medium | — | — |
| `CVE-2099-0016` | NVD | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | medium, from its SUSE assessment | `CWE-125` | — |
| `CVE-2099-0017` | NVD | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | medium | — | — |
| `CVE-2099-0018` | Manual Ticket creation | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | critical | `CWE-287` | NVD after the Ticket creation. EPSS: score `0.31`, percentile `0.92`, assessed `D − 1` |
| `CVE-2099-0019` | Manual Ticket creation | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | high | — | NVD after the Ticket creation |
| `CVE-2099-0020` | Manual Ticket creation | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | medium | — | NVD after the Ticket creation |
| `CVE-2099-0021` | NVD | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` | low | — | — |
| `CVE-2099-0022` | NVD | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | high | — | — |
| `CVE-2099-0023` | NVD | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | medium | — | — |

The Severity column is the resolved Ticket severity after the load
(`docs/features/tickets/cvss-scoring.md`, Severity Resolution Cascade).

Every ingestion is one system call of `upsert_cve()` with the source member of
its column (`CVESourceType.NVD`, `MITRE`, `KEV`, `EPSS`, or `GHSA`), followed
in the same transaction by `upsert_references()` when the CVE has automatic
references (References). The `CVEs and tickets` step runs:

1. the first ingestion of `CVE-2099-0001` to `CVE-2099-0017`, in order;
2. the manual Ticket creations of Tickets, in order;
3. the first ingestion of `CVE-2099-0021` to `CVE-2099-0023`, in order; and
4. the further ingestions: NVD for `CVE-2099-0018` to `CVE-2099-0020`, then
   MITRE, KEV, EPSS, and GHSA, each in ascending CVE order.

The affected-version entry of `CVE-2099-0009` has the version type `semver`
and the status `affected`. The automatic references of References are applied
with no source reference.

The SUSE assessments are part of the Ticket work:

| CVE | SUSE vector | By |
|---|---|---|
| `CVE-2099-0013` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | `asmith` |
| `CVE-2099-0014` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | `asmith` |
| `CVE-2099-0015` | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | `bwilson` |
| `CVE-2099-0016` | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | `asmith` |

Each is one `upsert_cvss_assessment()` with the `MANUAL_SUSE` caller.

### Tickets

On a newly created database the Tickets receive the identifiers `SNTL-1` to
`SNTL-25` in this order. Every Ticket with a CVE is created by the first
ingestion of its CVE, except `SNTL-18` to `SNTL-20`; every Ticket without a CVE
is created manually. The table states the final state after the load.

The dataset holds more than one page of Tickets at the default page size of
20 (`docs/api-spec.md`) for every caller: 23 Tickets are not confidential and
are visible without authentication.

| Ticket | CVE | Created by | Status | Assignee | Confidential | Severity |
|---|---|---|---|---|---|---|
| `SNTL-1` to `SNTL-7` | `CVE-2099-0001` to `CVE-2099-0007` | Ingestion | `New` | — | No | As CVEs |
| `SNTL-8` | `CVE-2099-0008` | Ingestion | `Ignored`, because its CVE is rejected | — | No | unresolved |
| `SNTL-9`, `SNTL-10` | `CVE-2099-0009`, `CVE-2099-0010` | Ingestion | `New` | — | No | As CVEs |
| `SNTL-11` | `CVE-2099-0011` | Ingestion | `Analysis` | `bwilson` | No | high |
| `SNTL-12` | `CVE-2099-0012` | Ingestion | `Analysis` | `asmith` | No | high |
| `SNTL-13` | `CVE-2099-0013` | Ingestion | `Analyzed` | `asmith` | No | high |
| `SNTL-14` | `CVE-2099-0014` | Ingestion | `Resolved` | `asmith` | No | high |
| `SNTL-15` | `CVE-2099-0015` | Ingestion | `Resolved` | `bwilson` | No | medium |
| `SNTL-16` | `CVE-2099-0016` | Ingestion | `Resolved` | `asmith` | No | medium |
| `SNTL-17` | `CVE-2099-0017` | Ingestion | `Ignored` | `bwilson` | No | medium |
| `SNTL-18` | `CVE-2099-0018` | `asmith` | `Analysis` | `asmith` | Yes, with a coordinated release date `T + 30d` and an access grant to `cwhite` | critical |
| `SNTL-19` | `CVE-2099-0019` | `bwilson` | `Analysis` | `bwilson` | Yes, without access grant | high |
| `SNTL-20` | `CVE-2099-0020` | `cwhite` | `New` | — | No | medium |
| `SNTL-21` | — | `asmith`, with the manual severity high | `Analysis` | `asmith` | No | high |
| `SNTL-22` | — | `bwilson` | `Duplicated`, a duplicate of `SNTL-21` | `bwilson` | No | unresolved |
| `SNTL-23` to `SNTL-25` | `CVE-2099-0021` to `CVE-2099-0023` | Ingestion | `New` | — | No | As CVEs |

The manual Ticket creations are `create_ticket()` calls with the `manual`
source by the creator of the table, with the CVE and the manual severity of
the table. Only `SNTL-18` is created confidential, with its coordinated
release date; `SNTL-19` is created non-confidential and made confidential by
the Ticket work. A creator who holds the `vulnerability_analyst` role is
assigned and the Ticket starts in `Analysis`; `cwhite` is not, and `SNTL-20`
stays `New` (`docs/features/tickets/tickets.md`, Manual Creation).

Operations of the `Ticket work` step, in this order. Every operation without a
named user is a system operation (Attribution).

| Ticket | Operations |
|---|---|
| `SNTL-11` | `bwilson` adds `fictional-curl` (Packages, Tracks, and Maintainers). `bwilson` sets the `fles-16.0` track to `AFFECTED` |
| `SNTL-12` | `bwilson` assigns the Ticket to `asmith`. `bwilson` sets the priority override `P1`. `asmith` adds the manual reference of References |
| `SNTL-13` | `asmith` adds `fictional-httpd`, sets its track to `AFFECTED`, and adds the SUSE assessment. The IBS observations of `SNTL-13` are applied in order (IBS Requests) |
| `SNTL-14` | `asmith` adds `fictional-libxml`, sets its track to `AFFECTED`, and adds the SUSE assessment. The IBS observations of `SNTL-14` are applied in order. Track release detection sets the track to `FIXED`. Product release detection confirms the release of `Server 15 SP7` at `T − 2d` with the advisory `SUSE-SU-2099:0001-1` |
| `SNTL-15` | `bwilson` adds `fictional-sudo`, sets the `fles-16.0` track to `NOT_AFFECTED` and the `SUSE:FLES-15-SP4:Update` track to `WONT_FIX`, and adds the SUSE assessment |
| `SNTL-16` | `asmith` adds `fictional-kernel`, sets the `SUSE:FLES-15-SP5:Update` track to `AFFECTED`, and adds the SUSE assessment |
| `SNTL-17` | `bwilson` ignores the Ticket |
| `SNTL-18` | `asmith` adds `fictional-openssh` and sets its track to `AFFECTED`. The IBS observations of `SNTL-18` are applied in order. `asmith` grants access to `cwhite` |
| `SNTL-19` | `bwilson` makes the Ticket confidential |
| `SNTL-22` | `bwilson` marks the Ticket as a duplicate of `SNTL-21` |

The operations use `add_package_records()`, `set_track_status()`,
`upsert_cvss_assessment()`, `assign_ticket()`, `set_priority_override()`,
`create_reference()`, `ignore_ticket()`, `grant_access()`,
`set_confidentiality()`, `mark_as_duplicate()`, `set_product_released_at()`,
and `apply_ibs_request_observation()`. Track release detection is
`set_track_status()` with `FIXED` and no acting user.

The resulting states follow the gates of `docs/features/tickets/tickets.md`:

- `SNTL-11` stays in `Analysis` because its `SUSE:FLES-15-SP7:Update` track is
  in `ANALYSIS`.
- `SNTL-13` is `Analyzed`: its `AFFECTED` track has the eligible, unreleased
  Product `Server 15 SP7`.
- `SNTL-14` is `Resolved` through a `FIXED` track whose only eligible Product
  is released.
- `SNTL-15` is `Resolved` through `NOT_AFFECTED` and `WONT_FIX` tracks.
- `SNTL-16` is `Resolved` through an `AFFECTED` track without an eligible
  Product: its SUSE score `5.5` is below the threshold `7.0` of
  `Server LTSS 15 SP5`. Its `SUSE:FLES-15-SP3:Update` track stays in
  `ANALYSIS` and is not actionable, because its only Product is EOL.
- `SNTL-18` and `SNTL-19` stay in `Analysis` without a SUSE assessment.

### Packages, Tracks, and Maintainers

Each package is added by one `add_package_records()` call by the user of
Tickets, with the tracks and Products below; `maintainer_emails` contains
`dave.brown@example.com` where the Maintainer column says `dbrown`. A track's
delivery status is `PENDING` unless IBS Requests changes it.

| Ticket | Package | Workflow | Track | Products | Track status | Delivery | Maintainer |
|---|---|---|---|---|---|---|---|
| `SNTL-11` | `fictional-curl` | `git` | `fles-16.0` | `Server 16.0`, `Micro 6.2` | `AFFECTED` | `PENDING` | `dbrown` |
| | | `ibs` | `SUSE:FLES-15-SP7:Update` | `Server 15 SP7` | `ANALYSIS` | `PENDING` | |
| `SNTL-13` | `fictional-httpd` | `ibs` | `SUSE:FLES-15-SP7:Update` | `Server 15 SP7` | `AFFECTED` | `IN_PROGRESS` | `dbrown` |
| `SNTL-14` | `fictional-libxml` | `ibs` | `SUSE:FLES-15-SP7:Update` | `Server 15 SP7`, released | `FIXED` | `RELEASED` | `dbrown` |
| `SNTL-15` | `fictional-sudo` | `git` | `fles-16.0` | `Server 16.0`, `Micro 6.2` | `NOT_AFFECTED` | `PENDING` | — |
| | | `ibs` | `SUSE:FLES-15-SP4:Update` | `Server LTSS 15 SP4`, not eligible | `WONT_FIX` | `PENDING` | |
| `SNTL-16` | `fictional-kernel` | `ibs` | `SUSE:FLES-15-SP5:Update` | `Server LTSS 15 SP5`, not eligible | `AFFECTED` | `PENDING` | — |
| | | `ibs` | `SUSE:FLES-15-SP3:Update` | `Server 15 SP3`, EOL | `ANALYSIS` | `PENDING` | |
| `SNTL-18` | `fictional-openssh` | `ibs` | `SUSE:FLES-15-SP7:Update` | `Server 15 SP7` | `AFFECTED` | `IN_PROGRESS` | `dbrown` |

A Product is eligible unless the table states otherwise
(`docs/features/packages/package-model.md`, Axis 2: Eligibility): `Server LTSS
15 SP4` is in Reactive Support, and the SUSE score of `CVE-2099-0016` is below
the threshold of `Server LTSS 15 SP5`.

The maintainer workbench of `dbrown` (`docs/features/packages/maintainer.md`,
Classification) therefore holds one pending item (`SNTL-11`, `fles-16.0`),
two in-progress items (`SNTL-13` and `SNTL-18`), and one completed item
(`SNTL-14`). `dbrown` sees the confidential `SNTL-18` through maintainership.

### IBS Requests

| Request | Type | Ticket | Incident | Upstream created | Final state |
|---|---|---|---|---|---|
| `900000` | `maintenance_incident` | `SNTL-13` | — | `T − 20d` | `declined` |
| `900001` | `maintenance_incident` | `SNTL-13` | — | `T − 5d` | `review` |
| `900002` | `maintenance_incident` | `SNTL-14` | `90001` | `T − 12d` | `accepted` |
| `900003` | `maintenance_release` | `SNTL-14` | `90001` | `T − 6d` | `accepted` |
| `900004` | `maintenance_incident` | `SNTL-18` | `90002` | `T − 9d` | `accepted` |
| `900005` | `maintenance_release` | `SNTL-18` | `90002` | `T − 2d` | `new` |

The evidence arrives as the sequence of complete observations that the shared
reconciliation would make over the history of the requests
(`docs/features/packages/ibs-submission-tracking.md`, Required Roots and
Delivery Derivation). Each observation is one system operation of
`apply_ibs_request_observation()`; it holds the listed requests in the listed
state, with that state's upstream update time:

| Ticket | Observation | Requests | Delivery |
|---|---|---|---|
| `SNTL-13` | 1 | `900000` `review` (`T − 19d`) | `IN_PROGRESS` |
| `SNTL-13` | 2 | `900000` `declined` (`T − 18d`); `900001` `review` (`T − 4d`) | `IN_PROGRESS` |
| `SNTL-14` | 1 | `900002` `review` (`T − 11d`) | `IN_PROGRESS` |
| `SNTL-14` | 2 | `900002` `accepted` (`T − 10d`); `900003` `new` (`T − 6d`) | `IN_PROGRESS` |
| `SNTL-14` | 3 | `900003` `accepted` (`T − 3d`), its release proven | `RELEASED` |
| `SNTL-18` | 1 | `900004` `review` (`T − 9d`) | `IN_PROGRESS` |
| `SNTL-18` | 2 | `900004` `accepted` (`T − 8d`); `900005` `new` (`T − 2d`) | `IN_PROGRESS` |

A `review` SR, an effective accepted SR, and a `new` RR establish progress, a
proven release establishes `RELEASED`, and a later observation holds only the
requests whose evidence it observes anew, as Required Roots defines: the
proving RR alone for a proven release.

Every request has one action, for the package of its Ticket `L` in the
codestream `SUSE:FLES-15-SP7:Update`, with the values of
`docs/features/packages/ibs-submission-tracking.md` (Package and Codestream
Identity, IBSRequestAction):

- a `maintenance_incident` action has the source project
  `SUSE:FLES-15-SP7:Branches`, a `SUSE:` project whose open request diff IBS
  makes available (`docs/features/integrations/ibs-integration.md`, Request
  Action Diff), the source package `L.SUSE_FLES-15-SP7_Update`, and the target
  release project
  `SUSE:FLES-15-SP7:Update`; when accepted, also the target project
  `SUSE:Maintenance:{incident}` and the target package
  `L.SUSE_FLES-15-SP7_Update`;
- a `maintenance_release` action has the source project
  `SUSE:Maintenance:{incident}`, the source package
  `L.SUSE_FLES-15-SP7_Update`, the target project `SUSE:FLES-15-SP7:Update`,
  and the target package `L.{incident}`; and
- an accepted action carries the incident of the first table and acceptinfo:
  the revision `1` and the checksum formed by the request number left-padded
  with zeros to 32 digits, for example `00000000000000000000000000900002`. An
  action that is not accepted carries no acceptinfo, and a
  `maintenance_incident` action that is not accepted carries no incident.

### References

- `CVE-2099-0001` has two automatic references from its first ingestion,
  applied by `upsert_references()` with the source `sync_nvd_cves`, the name
  of the fetcher of the represented source:
  `https://www.example.com/advisories/CVE-2099-0001` with the upstream tag
  `Vendor Advisory`, and
  `https://git.example.com/fictional-lib/commit/0123abc` with the upstream tag
  `Patch`.
- `SNTL-12` has one manual reference by `asmith`:
  `https://bugzilla.example.com/show_bug.cgi?id=1000012`, titled
  `Fictional bug report`, of type `issue`.

### Audit Trails

The load writes no audit event itself. The delegated services create every
event of their contracts, so every audit trail of
`docs/features/platform/audit-trail-infrastructure.md` (Audit Trail Index)
holds events after the load:

| Audit trail | Events from the dataset |
|---|---|
| Identity | `user_created`, `role_added`, and `user_deactivated` |
| Setting | Two `setting_changed` events by `jdoe` |
| Fetcher | One `disabled` event by `jdoe` for every fetcher |
| Ticket | The events of every Ticket creation and Ticket work operation, for example `ticket_created`, `assignment`, `status_change`, `cve_associated`, `cvss_assessment_changed`, `product_eligibility_changed`, `package_added`, `package_maintainer_added`, `track_status_changed`, `product_released`, `priority_changed`, `reference_added`, `coordinated_release_changed`, `confidentiality_changed`, `access_grant_added`, and `duplicate_set` |

## Operating a Dataset Backend

A dataset backend runs the API process; the Celery worker and Beat may run, and
find no enabled fetcher. The IBS RabbitMQ consumer is not needed and is run,
if at all, with `IBS_RABBITMQ_ENABLED=false`
(`docs/features/integrations/ibs-rabbitmq-integration.md`). Users sign in
through local authentication with the Credentials above.

Operations that need an external source do not complete on a dataset backend:

- adding a package through the API queries SMELT and fails
  (`docs/features/packages/package-service.md`, `add_package_to_ticket()`);
- an on-demand CVE refetch reports every source as disabled;
- a manual fetcher trigger is rejected, because the fetcher is disabled; and
- enabling a fetcher would contact its external source, and is not done on a
  dataset backend.

Operations that publish a Celery task, such as the recalculation of the default
CVSS version, wait for a Celery worker.

## Drift Protection

The dataset changes with Sentinel. Two tests of
`docs/features/platform/testing-strategy.md` (Mandatory Test Scenarios →
Example Dataset) keep it aligned:

- the load test loads the complete dataset in every test run and compares the
  result with Dataset Content, so a change that breaks the load or alters its
  result fails the pull request that makes it; and
- the coverage test derives the tables and the enumerations that the dataset
  must cover from the code, so a new table or enumeration value fails it until
  the dataset covers it or its exception list names it.

A capability that the UI needs and the dataset lacks is requested as a change
of this specification.

## Security Considerations

- **Known credentials (accepted risk)**: every dataset user, the administrator
  included, has the published password of Credentials. Anyone who reaches the
  API of a dataset backend can sign in as any active dataset user. A dataset
  backend MUST therefore be reachable only from the developer's host or from
  inside its test environment, never from a shared network: its API port is
  published on the loopback interface only (`docs/deployment.md`, Loading the
  Example Dataset).
- **Empty-database guard**: the load refuses a non-empty database
  (Empty-Database Guard), so it never adds known credentials to an
  installation in use.
- **Residual risk (accepted)**: an operator who loads the dataset into a newly
  created staging or production database creates an administrator with a
  public password. The command has no configuration switch against this:
  the dataset is documented for development and test environments only, and
  `docs/deployment.md` requires verifying that no dataset user exists, in the
  Staging-Specific Notes and in the Pre-Production Checklist.
- **No real data**: every identifier is fictional, and every email address
  uses `example.com`, so no message from a dataset backend reaches a real
  person.
- **No secret**: the dataset contains no credential other than its public
  password and reads none from the environment.

## Cross-references

- `docs/architecture.md` — System Boundary; Backend Layer Architecture
- `docs/cli-reference.md` — `sentinel example-data load`
- `docs/deployment.md` — Loading the Example Dataset; Pre-Production Checklist
- `docs/conventions.md` — CLI Conventions; Example Data in Documentation;
  Caller-Owned Service Transactions
- `docs/features/platform/cli-infrastructure.md` — shared CLI mechanism
- `docs/features/platform/testing-strategy.md` — Example Dataset scenarios
- `docs/features/identity/rbac.md` — Predefined Roles
- `docs/features/identity/local-authentication.md` — local sign-in
