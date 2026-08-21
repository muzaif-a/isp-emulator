# Detection & Analysis Model

How labeled per-packet CSV becomes a trained detector, a benchmark against
baselines, and a forensic match — with the exact protocol that keeps the result
honest. Read top to bottom.

---

## 1. What this produces

Three results, in order of value:

1. **Detection** — decide whether a flow carries the hidden timing signal.
2. **Benchmark** — show the proposed model against strong classical baselines under
   a protocol that resists over-optimistic scores.
3. **Attribution** — match a signal seen at one observation point to the same signal
   seen at another, with an exact statistical bound.

```
CSV → inter-packet delays (IPD) → windows → train/eval → benchmark → attribution
```

**Guiding rule.** The frozen numbers in the preregistration (input length, clip,
threshold, seeds, success criteria) are fixed **before** looking at results.
Changing them after seeing results is p-hacking. Respect the freeze.

---

## 2. From CSV to model input

### 2a. Extract inter-packet delays (IPD)

For the flow of interest, take packet timestamps and compute the gap between
consecutive packets in milliseconds. That gap sequence — the **IPD sequence** — is
the *only* thing the model sees.

Two cleaning rules that decide correctness:

- Extract IPDs from a **single observation point's file**, never a merged file (a
  merged file contains duplicate packets that corrupt the gaps).
- **Drop retransmissions and duplicates** first — a retransmitted large packet
  otherwise inserts a false beat into the sequence.

### 2b. Normalize (frozen spec)

```
clip each IPD to [0, 100] ms   →   divide by 100   →   left-pad with 0.0 to length 64
```

Length 64 is the 95th percentile of real sequence lengths. Left-padding puts the
most recent gaps on the right.

### 2c. Window — do NOT use one sample per session (current bug)

A single flow yields 400+ IPDs. Taking only the last 64 throws away ~85% of it and
gives **one training sample per session** — far too few for a ~35,000-parameter
model (rule of thumb: needs 350+ samples).

**Fix:** slide a length-64 window across each sequence to get ~6 samples per flow.
252 flows then yields ~1,500 samples.

**Hard rule to prevent leakage:** all windows from one flow go **entirely** into
train **or** test — never split a single flow's windows across both. Splits happen
at the flow level, not the window level.

---

## 3. The proposed model (frozen architecture)

A 1-D convolutional network over the IPD sequence. Input only — no other fields.

```
Input (64, 1)
  → Conv1D(32, kernel 3, ReLU, L2 1e-4) → BatchNorm → MaxPool(2)
  → Conv1D(64, kernel 5, ReLU, L2 1e-4) → BatchNorm → GlobalAveragePooling
  → Dense(64, ReLU, L2 1e-4) → Dropout(0.5)
  → Dense(1, Sigmoid)
```

Why this shape: the first conv detects adjacent short/long transitions; the second
detects longer sub-patterns; global pooling makes it position-invariant and
length-tolerant; dropout is the main defense against overfitting on a small set.

**Training (frozen):** Adam lr 1e-3, batch 16, up to 200 epochs, EarlyStopping on
validation AUC (patience 20), ReduceLROnPlateau (patience 10), class-balanced
weights, seed 42, validation split at the **flow** level.

**What it learns — state this precisely.** It learns that the gaps are artificially
**bimodal** (clustered at two values) instead of naturally continuous. It does
**not** and **cannot** read the hidden bit sequence — that sequence is
cryptographically pseudorandom, so predicting it is impossible. Decoding a known
signal to bits is a trivial threshold, not learning. Keep the language exact:
*the model detects a discretized timing structure; it never reads the message.*

---

## 4. Baselines to beat

The proposed model must be compared against classical detectors on identical data
and the identical protocol. Report the proposed model only if it clears the
preregistered margin over the best of these:

| Baseline | Idea |
|---|---|
| Threshold | Fixed cut on the gap value |
| Likelihood-ratio test | Probability of the sequence under signal vs no-signal models |
| Matched filter | Correlate against the expected pattern |
| Dynamic time warping | Elastic distance to a reference pattern |
| Shannon entropy | Randomness of the gap distribution |
| Random forest | Tree ensemble on summary statistics of the sequence |

Add a strong modern sequence-classifier baseline (a random-convolution-kernel method
such as MiniROCKET) — it is fast, needs little tuning, and often matches deep models
on small data. If it ties the proposed model, **say so**; "a simple method matches
the deep one" is a clean, honest finding.

---

## 5. Evaluation protocol (this is what makes it publishable)

### 5a. Split by condition, not at random

A random split lets near-identical windows land in both train and test and inflates
every score. The primary protocol is **leave-one-condition-out**: train on some
conditions, test on a held-out one.

| Protocol | Train | Test | Question it answers |
|---|---|---|---|
| Primary | low + medium load | high load | Does it survive heavier noise? |
| Secondary | one tunnel mode | another tunnel mode | Does it transfer across tunnels? |
| Secondary | one sender | another sender | Is it sender-independent? |
| Diagnostic only | random 75/25 | (label as optimistic) | Upper bound, not the headline |

### 5b. Metrics that respect rarity

The signal is rare in the wild, so accuracy lies. Lead with **PR-AUC** and
**detection rate at a fixed false-positive rate**. Also report F1, precision,
recall, false-positive and false-negative rate, ROC-AUC, MCC, Cohen's κ, and a
calibration curve. Evaluate at realistic prevalence, not a balanced 50/50 test set.

### 5c. Statistics

Bootstrap 95% confidence intervals; paired significance test between models across
flows; correct for multiple comparisons; report effect sizes, not just p-values.

### 5d. Leakage audits (run and report all three)

1. **Shuffle labels** → the model must collapse to chance. If it doesn't, something
   leaks.
2. **Confirm the input is IPD-only** — no packet size, port, address, marker, or TTL
   reaches the model.
3. **Confirm flow-level splitting** — no flow's windows straddle train and test.

---

## 6. The generalization gate (do this early — it can change the story)

Because the signal is generated by one specific encoding, a detector can secretly
learn *that encoder's fingerprint* rather than "hidden timing" in general. Guard
against it:

- Implement **multiple signal encodings** (the current bimodal one, a
  jitter-style one, a model-based one, a randomized-delay one) behind one interface.
- **Train on one encoding, test on another.** If a detector using
  distribution/periodicity structure holds up, the result is real. If it collapses
  toward chance, the detector had memorized the encoder — better to learn that now
  than at review.

This test is the single highest-information experiment. Run it before investing in
everything downstream.

---

## 7. Attribution (the forensic result)

Matching the same signal observed at two points is *easier* than detection: both
observations are of the same event, so only the segment between the two observation
points adds noise, and no model of "normal" is needed.

**Method — use an exact statistic, not a learned score.** Decode both observed
sequences to bits (a simple threshold) and compare with Hamming distance. Under the
null hypothesis "these two flows are unrelated," the probability of a chance match
is an exact binomial:

| Bits compared | Agreement | P(random match) |
|---|---|---|
| 100 | 70% | ~1e-5 |
| 400 | 70% | ~1e-16 |
| 400 | 89% | ~1e-55 |

Flows here carry 400+ bits, so the bound is extremely strong. "The probability these
flows are unrelated is below 1e-16" is far better forensic evidence than "the model
output 0.97."

**Why offsets don't matter.** Comparing the *gaps* cancels any constant time offset
between the two observation points, and realistic clock drift over a short flow is
microseconds against tens-of-milliseconds bits — negligible.

**The real risk to test — multiplexing.** If the observed outer stream carries only
the signal flow, matching is trivial (and unrealistically easy). If it interleaves
several flows, the signal is buried and simple bit-matching fails. Required
experiment: **how many concurrent flows before matching breaks?** This is the one
place a learned matcher may beat the exact statistic, and thus the justification for
a deep matcher in this stage.

**Prior art to cite and differentiate from:** deep flow-correlation for anonymity
systems already exists. The novelty here is not "correlate flows" — it is
correlating a *hidden timing signal* across an encrypted-and-decrypted observation
pair for **attribution**, backed by an exact bound.

---

## 8. Sample size

The preregistration sets the target by a power analysis: **160 flows minimum** (4
load levels × 20 signal flows, plus 80 no-signal flows), **252 preferred**. Below
this the confidence intervals are too wide to support the claims. Generate to the
target before reporting any headline number.

---

## 9. One integrity item

The frozen decision threshold (the gap value separating short from long) and the
pilot signal-integrity figure are cited as coming from an exploratory-analysis
output file. **That file must actually exist and be regenerable.** Regenerate it
from the pilot data; if the threshold shifts, document the change openly. A released
preregistration invites others to ask for the analysis behind every frozen number.

---

## 10. Build order

1. Run the exploratory analysis over the parsed data; regenerate the analysis output
   file; verify the frozen threshold (Section 9).
2. **Fix windowing** so each flow yields multiple samples, split at the flow level
   (2c).
3. Run the full leave-one-condition-out evaluation with all baselines and the
   proposed model; produce confidence intervals and significance tests (Sections 4,
   5).
4. Run the three leakage audits (5d) — do not trust any score until these pass.
5. Run the **generalization gate** (Section 6). Pivot the narrative if it fails.
6. Build the attribution match and the multiplexing-robustness experiment (Section
   7).
7. Add the modern sequence-classifier baseline and finalize the benchmark table.
