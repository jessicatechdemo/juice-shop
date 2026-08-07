# Finding discovery

The exact tip-to-tip diff contains one changed source file, `routes/search.ts`, and it was read in full together with the exact diff and minimum supporting route/parser/error-handling context.

One candidate survives discovery: target line 21 removes the base revision's runtime string-type guard for the anonymous `q` query parameter. Express extended query parsing permits arrays and objects, so target line 22 applies string operations and a character-count control to attacker-selected non-string values. This can produce deterministic request failures and lets repeated-value arrays bypass the intended 200-character bound before SQL interpolation. The SQL injection at line 23 is intentionally present in both revisions and is not itself a diff finding.
