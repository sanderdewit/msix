# Roadmap

Everything from the original feature roadmap (v0.9 → v0.73) has shipped —
see [CHANGELOG.md](CHANGELOG.md) for the full history and
[GitHub issues](https://github.com/sanderdewit/msix/issues) for anything
in flight. This file now tracks only the path to **1.0**.

## Path to 1.0

1.0 is a promise the heuristics survive contact with reality, not a feature
drop. Gates, in order of importance:

- [ ] **Field proofing** — a corpus of 100+ real vendor packages through
      investigate → autofix → `Test-MsixDeployment` with a published pass
      rate. Every failure becomes a trait-based heuristic + a synthetic
      regression fixture (never an app-specific recipe — see the
      generalization rule below).
- [ ] **Hyper-V runtime path validated** — TEST-PLAN Scenario 14 executed on
      a real lab host (the orchestration is unit-tested against a mocked VM
      seam; the hypervisor path itself has not run yet).
- [ ] **API freeze** — semver commitment, rename freeze (the alias list
      settles), documented deprecation policy.
- [ ] **Signed module** — publish the PSGallery module Authenticode-signed
      (the tooling preaches signing; it should be signed).
- [ ] **Security review round** over the newest surface (bundles, runtime
      testing, SignerSignEx, frameworks, modification packages).
- [ ] **Deferred:** raw `mssign32!SignerSignEx2` APPX-SIP P/Invoke — needs a
      trusted code-signing cert to validate (a subtly wrong appx signature
      installs as corrupt). The shipped SignerSignEx backend already closes
      the password-on-command-line exposure in-process.

## The generalization rule (field hardening)

Every field lesson must become a **trait-based heuristic**, never a
name-based recipe: scanners may only key on things any package can exhibit
(registry shapes, file-layout patterns, manifest structures, PE imports).
Playbooks are the pressure valve for the genuinely app-specific — treat each
one as a failed generalization and periodically dissolve it into a scanner
rule. Unification metric: % of the corpus fully fixed with zero playbook
hits.
