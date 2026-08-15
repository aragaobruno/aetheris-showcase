# The OBSERVED / INFERRED invariant

*Engineering note — AETHERIS*

Most security tooling records two very different things in the same place, at the same
level of trust: what it *measured*, and what it *concluded*. AETHERIS refuses to. That
refusal is the single most important design decision in the system, and it matters more,
not less, once a language model is anywhere in the pipeline.

## Two things that are not the same

Consider a real observation from testing. A server responds to a request carrying
`Origin: https://evil.example.com` by reflecting that exact origin back in
`Access-Control-Allow-Origin`, together with `Access-Control-Allow-Credentials: true`.

Two statements can be made about this:

- **Observed:** "The server reflected the attacker-supplied origin, with credentials
  enabled." This is a fact. It was measured over the network. It is either true or it is
  not, and it can be re-checked.
- **Inferred:** "This is an exploitable CORS misconfiguration, severity HIGH." This is a
  *judgment*. It might be right. It might also be wrong — the endpoint might serve no
  authenticated data, or the target might be an echo service where reflecting any origin is
  the intended behavior and there is nothing to steal.

The reflection is real. The severity is a guess about the reflection. Storing the guess as
if it were the fact is how a security report becomes noise — and how a hallucinated finding
becomes a permanent, official-looking record.

## Why this gets worse with an LLM in the loop

A language model is fluent and confident. Its inferences *read* like facts — same grammar,
same certainty, no hedging unless you force it. If you let a model write directly into your
system of record, you are letting confident prose set the trust level of your evidence. The
model's "this is exploitable" lands in the ledger looking exactly like the network's "this
header was present." That is precisely the failure a forensic record cannot tolerate.

## The invariant

AETHERIS separates the two categories structurally and enforces one rule at the data layer:

> A finding cannot be promoted to `CONFIRMED` unless it is anchored to at least one
> `OBSERVED` observation.

Findings are born `DRAFT`. An inferred severity is stored as `INFERRED`, explicitly
labeled. Promotion to `CONFIRMED` is an attested transition that requires an empirical
anchor — and the anchor proves only that *the behavior exists*, never that the risk rating
attached to it is correct. Those remain two separate claims, at two separate trust levels.

The key word is *invariant*, not *convention*. A convention is advice a tired engineer or
an eager model can ignore. An invariant is enforced by the layer below — the transition is
refused. The system is structurally incapable of recording a confident guess as a measured
fact.

## The general principle

Separate the layer that observes from the layer that judges, and make your record
physically unable to confuse them. It is a cheap discipline to design in and an expensive
one to retrofit — and in any pipeline where a model contributes, it is the difference
between an evidence system and an opinion generator with good formatting.
