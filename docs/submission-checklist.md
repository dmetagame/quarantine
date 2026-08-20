# Hack Hydra Submission Checklist

This checklist records what is verifiable from the current repository and
what still requires owner action. It does not substitute for the competition's
official submission form or rules.

Status notation: `[x]` is verified from this checkout; `[ ]` means the item
still requires owner or host-side action. A checked item may still include a
human confirmation note where repository inspection cannot establish legal or
competition ownership.

## Repository And Code

- [x] **Public GitHub repository** - created at
  <https://github.com/dmetagame/quarantine>. The refreshed live evidence
  validates, and the initial release is published on `main`.
- [x] **Open-source license file** - MIT license is present. NEEDS HUMAN ACTION
  to confirm that `Quarantine contributors` is the correct copyright notice.
- [x] **README** - judge-facing thesis, problem, solution, architecture,
  HydraDB rationale, setup, demo, evidence, and limitations are documented.
- [x] **Setup instructions** - `npm install`, HydraDB startup, validation,
  proof, and demo commands are documented and match `package.json`.

## Demonstration And Evidence

- [x] **Meaningful HydraDB use** - indexed selectors, reverse
  `DERIVES_FROM` traversal, multi-hop witnesses, and unresolved ancestry are
  part of the implementation and recorded proof artifacts.
- [x] **Dated proof artifacts present** - HydraDB, provenance-writer,
  action-gateway, and end-to-end demo reports are present under `evidence/`;
  rolling `latest-*` reports and local HydraDB data are excluded by
  `.gitignore`.
- [x] **Reproducible post-hardening live proof** - VERIFIED 2026-08-20 against
  the running `ghcr.io/hydra-db/hydradb:0.1.1` image and expected registry
  digest. HydraDB, provenance writer, action gateway, and both end-to-end demo
  scenarios passed. The gateway evidence also covers the bounded adapter
  timeout and indeterminate replay contract. `npm run validate:evidence`
  passed, and the required dated/latest evidence pairs are byte-identical.
- [x] **Three-minute demo script** - see `docs/demo-script.md`.
- [x] **Hosted demo deployment** - VERIFIED 2026-08-20 at
  <https://quarantine.rouma.online>. HTTPS and the certificate are valid;
  `VALID` returns `ALLOW`, `action.executed: true`, `adapter_calls: 1`, and
  `TAMPERED` returns `BLOCK_UNRESOLVED_ANCESTRY / DEPTH_CAP_REACHED`,
  `action.executed: false`, `adapter_calls: 0`. Re-run this smoke test after
  deploying the final local deadline fixes.
- [ ] **Demo video** - NEEDS HUMAN ACTION.

## Submission

- [ ] **Hack Hydra track and rules confirmation** - NEEDS HUMAN ACTION. Track
  fit, eligibility, public-repository timing, and prohibited pre-hackathon
  work cannot be established from this checkout.
- [x] **Final repository URL** - <https://github.com/dmetagame/quarantine>.
- [x] **Initial public release commit** - `0389490` (`Initial Hack Hydra
  release`) is pushed to `main`.
- [ ] **Final deployment/submission tag** - PENDING until the hosted demo is
  deployed and revalidated.
- [ ] **Submission form** - NEEDS HUMAN ACTION.

## Required Host-Side Release Run

From a host shell with Docker and localhost access, run the following from a
clean checkout and retain the resulting output before creating or pushing the
public repository:

```bash
npm install
./scripts/start-hydradb.sh
npm run test:demo
npm run proof:hydradb
npm run test:provenance
npm run test:gateway
npm run check
npm run test:unit
npm audit --omit=dev --audit-level=high
npm run validate:evidence
npm run demo
```

Do not manually edit evidence JSON. The proof runners must regenerate it.

After the run, confirm that the provenance, gateway, and demo dated/latest
pairs are byte-identical, that both HydraDB reports pass their structural
assertions, and that `npm run validate:evidence` passes.

## Reproducing The Initial Repository Release

The initial public repository has already been created. These are the commands
used to review and publish it after the live gate passed:

```bash
git add .
git status --short
git diff --cached --stat
git commit -m "Initial Hack Hydra release"
git branch -M main
gh auth status
gh repo create quarantine --public --source=. --remote=origin --push
git remote -v
git status
git log --oneline -1
```

The `gh repo create` command creates the repository under the currently
authenticated account. Confirm that account before running it; do not add or
invent an organization.
