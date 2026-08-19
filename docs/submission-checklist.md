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
  validates; the initial commit and push are tracked separately below.
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
- [x] **Reproducible post-hardening live proof** - VERIFIED 2026-08-19 against
  the running `ghcr.io/hydra-db/hydradb:0.1.1` image and expected registry
  digest. HydraDB, provenance writer, action gateway, and both end-to-end demo
  scenarios passed. `npm run validate:evidence` passed, and the required
  dated/latest evidence pairs are byte-identical.
- [x] **Three-minute demo script** - see `docs/demo-script.md`.
- [ ] **Hosted demo deployment** - PENDING. The local live demo is verified;
  a public hosting target and HydraDB runtime still need to be selected and
  deployed before submission.
- [ ] **Demo video** - NEEDS HUMAN ACTION.

## Submission

- [ ] **Hack Hydra track and rules confirmation** - NEEDS HUMAN ACTION. Track
  fit, eligibility, public-repository timing, and prohibited pre-hackathon
  work cannot be established from this checkout.
- [x] **Final repository URL** - <https://github.com/dmetagame/quarantine>.
- [ ] **Final commit or tag** - NEEDS HUMAN ACTION after review and commit.
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

## Owner Repository Release Commands

After the live gate passes and the copyright notice is confirmed, review the
staged file list before creating the first commit and public repository:

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
