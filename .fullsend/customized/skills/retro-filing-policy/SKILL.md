---
name: retro-filing-policy
description: >-
  Required on every Conforma retro run. Score every candidate from 0 to 5
  and file only score-4 and score-5 findings after duplicate checks.
---

# Conforma retro filing policy

This skill is mandatory for every retro run. Invoke it before writing
`$FULLSEND_OUTPUT_DIR/agent-result.json`. It augments the upstream retro
analysis and does not replace its workflow reconstruction, duplicate checks,
recently-closed checks, evidence handling, or proposal limit.

## Required filing sequence

1. Build the complete candidate list from the upstream retro analysis.
2. Before deciding what belongs in `proposals[]`, assign every candidate an
   integer judge score from 0 through 5 using the rubric below.
3. Apply the upstream checks for an existing open duplicate or a substantially
   equivalent issue closed recently. A duplicate or recently closed equivalent
   is summary-only even when its score is 4 or 5. Supporting evidence for an
   existing issue is summary-only and must never become an "Evidence for ..."
   proposal.
4. Put only eligible, non-duplicate candidates scored 4 or 5 in `proposals[]`.
   Preserve the upstream maximum of three proposals, keeping the highest-value
   candidates when there are more than three.
5. Keep every score-0-through-3 candidate out of `proposals[]`. Mention it in
   the retro `summary` as summary-only, with a compact reason.
6. In the `summary`, include a compact **Judge scores** list covering every
   candidate, filed and summary-only. Each entry must contain the score, a
   short title, and the disposition (`filed` or `summary-only`).
7. For every filed proposal, begin the existing
   `what_could_go_better` text field with:

   `Judge score: N/5 — <one-line justification>`

   Do not add new JSON fields or change the upstream result schema.

Do not create, edit, or post issues yourself. The upstream post-script handles
writes after output validation.

## Conforma scoring rubric

Score the impact of the candidate, not how interesting the observation is.
Use the lower range by default for isolated improvements:

- One-off pitfalls, cosmetic documentation edits, historical-document
  cleanup, speculative prevention rules, and isolated preferences score 0–3
  by default. They are not eligible for filing without evidence that a higher
  threshold applies.
- An `AGENTS.md` proposal scores 0–3 by default. It can score 4 or 5 only
  when there is evidence of a recurring contributor or agent failure, the rule
  applies to human contributors as well as bots, and the instruction has a
  credible preventive mechanism.

Use score 4 only when there is a likely recurring impact, such as repeated
human time loss, repeated bad bot output, pipeline or policy integrity risk,
or persistent operational cost.

Use score 5 only for a systemic or recurring correctness, security,
reliability, or policy failure.

A high score does not bypass the upstream duplicate, recently-closed, or
evidence-for checks. If those checks suppress a candidate, list it as
summary-only and explain the disposition in the summary.
