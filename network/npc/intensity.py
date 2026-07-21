"""
NPC intensity weight tables.

Behavior mix from CAIDA measurements:
  HTTP 65% | Bulk 15% | DNS 8% | FTP 5% | SMTP 5% | DB 2% | Idle remainder

Target ρ (link utilisation):
  low    → 0.20–0.30  (clean watermark, easy detection)
  medium → 0.50–0.70  (small queuing jitter perturbs IPDs)
  high   → 0.90–1.00+ (queue full → drops → rhythm noisy)
"""

# Integer weights used with random.choices().
# Idle weight fills remainder to hit target ρ.

WEIGHTS = {
    "low": {
        # ~20% active rounds (ρ ≈ 0.20)
        "http":  13,
        "bulk":  3,
        "dns":   2,
        "ftp":   1,
        "smtp":  1,
        "db":    1,
        "echo":  0,
        "idle":  79,
    },
    "medium": {
        # ~60% active rounds (ρ ≈ 0.60)
        "http":  39,
        "bulk":  9,
        "dns":   5,
        "ftp":   3,
        "smtp":  3,
        "db":    1,
        "echo":  1,
        "idle":  39,
    },
    "high": {
        # ~95%+ active rounds (ρ ≈ 0.95)
        "http":  65,
        "bulk":  15,
        "dns":   8,
        "ftp":   5,
        "smtp":  5,
        "db":    2,
        "echo":  2,
        "idle":  0,
    },
}

# Target ρ range per intensity (for documentation / validation)
RHO_TARGET = {
    "low":    (0.20, 0.30),
    "medium": (0.50, 0.70),
    "high":   (0.90, 1.00),
}

# Mean inter-arrival seconds per behavior (for exponential / uniform sampling).
# Scaled down from CAIDA field values to fit emulation capture windows (~15-25s).
# Relative ordering preserved: FTP/SMTP < bulk < HTTP/DNS.
INTER_ARRIVAL_S = {
    "http":  5,    # expovariate(1/5)
    "bulk":  15,   # expovariate(1/15)
    "dns":   4,    # expovariate(1/4)
    "ftp":   12,   # uniform(8, 20)
    "smtp":  10,   # uniform(5, 15)
    "db":    3,    # expovariate(1/3)
    "echo":  8,    # expovariate(1/8)
    "idle":  10,   # expovariate(1/10)
}

