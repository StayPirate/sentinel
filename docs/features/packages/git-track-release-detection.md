# Git Track-Level Release Detection

Release detection at the track level for the git workflow — the equivalent
of `ibs-track-release-detection.md` for IBS tracks.

**Status**: TBD — mechanism not yet defined.

## Context

This specification will define how Sentinel detects the affectedness and
delivery facts relevant to a git branch (e.g., `slfo-main`, `slfo-1.2`) on
`src.suse.de`. The future detector must compute each dimension from its own
authoritative evidence and route any effective mutation through the existing
package-service boundary with complete Ticket/package/track identity.

No coupling is defined yet between a source fix and delivery: this placeholder
does not require both dimensions to change together, define a direct
`PENDING -> RELEASED` transition, or define a Ticket audit event for delivery.
The future Git-specific evidence and transition contract must be completed
before implementation. If one workflow independently establishes more than one
result, it may persist them atomically without making either result an input to
the other.

See `docs/features/packages/package-model.md` for the package tracking
model, including the three orthogonal dimensions (affectedness,
eligibility, delivery) and the workflow-agnostic design that this
specification extends.

## Open Questions

- What mechanism detects changes in git branches? (webhook from
  src.suse.de? polling? event bus?)
- How is the CVE fix identified in a git commit? (commit message
  convention? changelog parsing? diff analysis similar to IBS?)
- Does Git release detection need track-specific source progress analogous to
  the IBS per-track checkpoint, or is its evidence mechanism fundamentally
  different? The IBS model is not a generic checkpoint abstraction.
- What is the periodic catch-up strategy? (equivalent of the 24h
  `detect_ibs_track_releases` fetcher for IBS)

## Cross-references

- `docs/features/packages/package-model.md` — package tracking model
  (owning specification)
- `docs/features/packages/ibs-track-release-detection.md` — IBS
  equivalent of this specification
- `docs/data-model.md` — TicketPackageTrack entity with `workflow_type`
  discriminator
