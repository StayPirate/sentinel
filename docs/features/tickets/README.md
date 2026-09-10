# Tickets

Core workflow entity — CVE ingestion, triage, severity, and audit trail.

## Specs

```
tickets.md              Ticket lifecycle, status gates, API endpoints
ticket-service.md       ticket_service module contract (Ticket lifecycle operations, cross-domain compositions)
ticket-mutations.md     ticket_mutations module contract (CVSS/severity mutations, status evaluation primitives)
cve-tracking.md         CVE tracking feature (business rules, API endpoints, CVE rejection handling)
cve-sync-nvd.md         NVD fetcher specification
cve-sync-mitre.md       MITRE cvelistV5 fetcher specification
cve-sync-kernel.md      Linux Kernel CNA fetcher specification
cve-sync-ghsa.md        GitHub Advisory DB fetcher specification
cve-sync-osv.md         OSV enrichment fetcher specification
cve-sync-redhat.md      Red Hat Security Data fetcher specification
cve-sync-kev.md         CISA KEV fetcher specification
cve-sync-epss.md        EPSS fetcher specification
cvss-scoring.md         Multi-provider CVSS assessments, severity resolution
ticket-audit-log.md     TicketAuditEvent audit trail, event type contract
ticket-references.md    External links on tickets (auto-classified by type, manual with manage_references capability)
```

## Relationships

- `tickets.md` is the central spec — it defines the ticket entity,
  status machine, gate conditions, and API endpoints.
- `ticket-service.md` is the service-layer companion for Ticket lifecycle
  operations and cross-domain compositions — it defines the `ticket_service`
  module contract (creation, CVE association, assignment, manual-zone entry and
  exit, confidentiality, access grants). Some operations compose package or
  CVSS boundaries with `reconcile_ticket_status` due to indirect gate effects.
- `ticket-mutations.md` is the service-layer companion for gate-relevant
  mutations — it defines the `ticket_mutations` module contract
  (CVSS/severity mutations, status evaluation primitives, concurrency control,
  `auto_assign_actor()`).
  Package-centric mutations are in `packages/package-service.md`.
- `cve-tracking.md` feeds tickets: each ingested CVE creates a ticket.
  Individual CVE fetcher specs follow common conventions defined in
  `docs/features/platform/cve-fetcher-infrastructure.md` (CVE Fetcher Conventions).
- `cvss-scoring.md` drives ticket severity and product eligibility
  (consumed by `tickets.md` and `packages/package-model.md`).
- `ticket-audit-log.md` defines the event contract that all ticket-mutating
  operations must satisfy.
