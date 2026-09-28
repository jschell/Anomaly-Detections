# Plan Workflow

Plans move through three directories:

- `queue/` — approved/planned work that has not started
- `active/` — work currently being implemented
- `complete/` — implemented and validated work

New plans should be created in `queue/`.

When implementation begins, move the entire plan file to `active/`. When its exit criteria are satisfied and validation is complete, move it to `complete/`.

The numeric plan prefix indicates intended execution order but does not prevent a later plan from being pulled forward when dependencies permit.

See [../overview.md](../overview.md) for the architecture and project boundaries.
