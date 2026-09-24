# Ideas

Brainstorming ideas for Sentinel. When an idea is promoted to a feature
specification, it should be removed from this list.

- There must be private tickets that will be visible only to certain logged-in users. This will be used mainly for embargoed tickets. During the creation of private tickets, verify that all other ways to access that information (API endpoints) are equally protected. Create unit tests for this and evaluate whether a sub-agent that verifies data protection could also be useful.
- Propose Sentinel command-line commands that could be useful
- Some codestreams/packages will need to be tracked even if they are not shipped in any product. For example go1.25
- Once all scheduled tasks (e.g. fetchers) are defined, review all schedule times and spread them out to avoid them all starting at the same moment
- The project is becoming very large and is composed only of specs. Define and maintain an intelligent implementation plan — a plan that allows implementing the platform one (or more) pieces at a time that can be tested before moving to the next piece.
- ~~Currently we are tracking two objects: Tickets and Packages. What if there were a third object? The Update. Already partially tracked by SRs, incidents, and RRs. The "released" status would belong to the Update and not to the Package.~~ → Promoted to spec: `docs/features/packages/package-model.md` (unified with package tracking redesign)
- ~~Expand the event system. Currently only TicketEvent exists, but other event types would make sense — for example, UserEvent to log modifications to a user, or events for admin operations such as creating or removing group-role mappings.~~ → Implemented: audit trail infrastructure (`docs/features/platform/audit-trail-infrastructure.md`), identity audit log (`docs/features/identity/identity-audit-log.md`), setting audit log (`docs/features/platform/system-settings.md`)
- ~~Investigate how application logs are handled. Where are they saved? When are they rotated? Backup?~~ → Promoted to spec: `docs/features/platform/logging.md`
- Periodically download all package maintainers and keep a local cache refreshed daily or weekly.
