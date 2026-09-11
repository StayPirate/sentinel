# Packages

Package affectedness, release and delivery reconciliation, product catalog,
and maintainership.

## Specs

```
package-model.md                      Status, eligibility, delivery, exclusion, actionability
├── ibs-track-release-detection.md       IBS track-level: existing-track reconciliation, expanded source diff, per-track checkpoint
├── ibs-product-release-detection.md     IBS product-level: deterministic repositories, validated updateinfo, exact source match
├── git-track-release-detection.md       Git track-level release detection (TBD)
├── git-product-release-detection.md     Git product-level release detection (TBD)
└── product-lifecycle-transitions.md     Reactive Support and EOL reconciliation

package-service.md                       package_service module contract (mutations, orchestration, queries)
product-catalog.md                       Product/ProductRepository, SMELT/AIMAAS sync, lifecycle phases
ibs-submission-tracking.md               IBS request-action evidence and authoritative track delivery reconciliation
package-maintainership.md                Package-wide maintainer acquisition and associations
maintainer.md                            Maintainer operations (pending fixes, in-progress, completed)
```

## Relationships

- `package-model.md` is the umbrella spec for the affectedness model.
  The two release-detection specs and the lifecycle-transitions spec
  implement specific automation described there.
- `product-catalog.md` owns the Product and ProductRepository entities,
  SMELT product sync, AIMAAS lifecycle/threshold sync, and the
  `GET /api/v1/products` endpoint. `package-model.md` consumes
  product data for eligibility evaluation and track-to-product mapping.
- `package-service.md` is the service-layer companion to
  `package-model.md` — it centralizes all package-centric mutations
  (track status, delivery, product eligibility, soft-delete/restore),
  orchestration (`add_package_to_ticket`), and query operations.
  Depends on `ticket_mutations.reconcile_ticket_status()`.
- `ibs-submission-tracking.md` owns IBS request/action persistence and track
  delivery reconciliation. Its daily fetcher is the correctness owner;
  package-add and Ticket-convergence catch-up, manual runs, and RabbitMQ request
  events accelerate the same reconciliation.
- `package-maintainership.md` owns SMELT-backed acquisition and the additive
  `TicketPackageMaintainer` relation used by confidential visibility and the
  maintainer workbench.
