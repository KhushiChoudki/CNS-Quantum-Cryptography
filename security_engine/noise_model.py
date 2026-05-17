"""
Noise Simulation & Statistical Analysis Module
================================================
Models quantum memory decoherence for MAQRAF.

Three noise scenarios:
  1. Benign client     — clean token, no noise
  2. Noisy client      — Gaussian bit-flip noise (models decoherence)
  3. Random attacker   — completely random token
  4. Partial attacker  — 50% knowledge + 50% guessed

Used for:
  - ROC curve generation (threshold vs. FPR/FNR)
  - Confidence distribution histograms
  - Noise tolerance analysis
"""

import random
import math
import hashlib


# ── Noise injection ────────────────────────────────────────────────────────────

def add_noise(token: list, noise_level: float = 0.05) -> list:
    """
    Gaussian-inspired bit-flip noise on token.
    noise_level = probability of each bit being flipped (models decoherence).

    Benign:    noise_level ≈ 0.00–0.05
    Moderate:  noise_level ≈ 0.10–0.15
    Adversarial: confidence drops below threshold statistically.
    """
    noisy = []
    for basis, bit in token:
        # Gaussian perturbation: sample actual flip prob from N(noise_level, sigma)
        sigma = noise_level * 0.3
        effective_p = max(0.0, min(1.0, random.gauss(noise_level, sigma)))
        flipped = 1 - bit if random.random() < effective_p else bit
        noisy.append((basis, flipped))
    return noisy


def add_basis_noise(token: list, basis_error_rate: float = 0.05) -> list:
    """
    Basis measurement error — models imperfect quantum channel.
    When basis is wrong, bit value is random (50/50).
    """
    bases = ['+', 'x']
    noisy = []
    for basis, bit in token:
        if random.random() < basis_error_rate:
            wrong_basis = [b for b in bases if b != basis][0]
            noisy.append((wrong_basis, random.randint(0, 1)))
        else:
            noisy.append((basis, bit))
    return noisy


# ── Confidence calculation (mirrors verifier logic) ───────────────────────────

def compute_confidence(stored_token: list, received_token: list) -> float:
    """Compute fraction of matching (basis,bit) pairs where bases align."""
    matches = total = 0
    for (sb, sv), (rb, rv) in zip(stored_token, received_token):
        if sb == rb:
            total += 1
            if sv == rv:
                matches += 1
    return matches / total if total > 0 else 0.0


# ── Statistical simulation engine ─────────────────────────────────────────────

def simulate_scenario(scenario: str, n_samples: int = 500, token_length: int = 16) -> list:
    """
    Simulate confidence scores for a given scenario.

    scenario options:
      'benign'       — clean token submission
      'noisy_05'     — 5% Gaussian bit-flip noise (decoherence)
      'noisy_15'     — 15% noise (heavy decoherence)
      'random'       — completely random token
      'partial_50'   — 50% known + 50% guessed
      'partial_75'   — 75% known + 25% guessed
    """
    scores = []
    bases  = ['+', 'x']

    for _ in range(n_samples):
        # Ground truth token
        stored = [(random.choice(bases), random.randint(0, 1)) for _ in range(token_length)]

        if scenario == 'benign':
            received = stored[:]

        elif scenario == 'noisy_05':
            received = add_noise(stored, noise_level=0.05)

        elif scenario == 'noisy_15':
            received = add_noise(stored, noise_level=0.15)

        elif scenario == 'random':
            received = [(random.choice(bases), random.randint(0, 1)) for _ in range(token_length)]

        elif scenario == 'partial_50':
            received = []
            for sb, sv in stored:
                if random.random() < 0.50:
                    received.append((sb, sv))
                else:
                    received.append((random.choice(bases), random.randint(0, 1)))

        elif scenario == 'partial_75':
            received = []
            for sb, sv in stored:
                if random.random() < 0.75:
                    received.append((sb, sv))
                else:
                    received.append((random.choice(bases), random.randint(0, 1)))
        else:
            received = stored[:]

        scores.append(compute_confidence(stored, received))

    return scores


def compute_roc(scores_positive: list, scores_negative: list, thresholds=None) -> dict:
    """
    Compute ROC curve.
    positive = benign/legitimate users
    negative = adversarial submissions

    Returns: {thresholds, tpr, fpr, fnr, tnr, auc}
    """
    if thresholds is None:
        thresholds = [i / 100 for i in range(0, 101, 2)]

    tpr_list, fpr_list, fnr_list = [], [], []

    for thresh in thresholds:
        # True positives (benign correctly accepted)
        tp = sum(1 for s in scores_positive if s >= thresh)
        fn = len(scores_positive) - tp
        # False positives (adversarial incorrectly accepted)
        fp = sum(1 for s in scores_negative if s >= thresh)
        tn = len(scores_negative) - fp

        tpr = tp / len(scores_positive) if scores_positive else 0
        fpr = fp / len(scores_negative) if scores_negative else 0
        fnr = fn / len(scores_positive) if scores_positive else 0

        tpr_list.append(round(tpr, 4))
        fpr_list.append(round(fpr, 4))
        fnr_list.append(round(fnr, 4))

    # AUC via trapezoidal rule
    auc = 0.0
    for i in range(1, len(fpr_list)):
        auc += abs(fpr_list[i] - fpr_list[i-1]) * (tpr_list[i] + tpr_list[i-1]) / 2

    return {
        "thresholds": thresholds,
        "tpr": tpr_list,
        "fpr": fpr_list,
        "fnr": fnr_list,
        "auc": round(auc, 4),
    }


def generate_full_analysis(n_samples: int = 300) -> dict:
    """
    Full statistical security analysis:
      - Confidence distributions for 4 scenarios
      - ROC curve (benign vs. random attacker)
      - Key metrics at 85% threshold
    """
    scenarios = {
        "benign":      simulate_scenario("benign",     n_samples),
        "noisy_05pct": simulate_scenario("noisy_05",   n_samples),
        "noisy_15pct": simulate_scenario("noisy_15",   n_samples),
        "random":      simulate_scenario("random",     n_samples),
        "partial_50":  simulate_scenario("partial_50", n_samples),
        "partial_75":  simulate_scenario("partial_75", n_samples),
    }

    def stats(scores):
        n   = len(scores)
        mu  = sum(scores) / n
        var = sum((s - mu) ** 2 for s in scores) / n
        sd  = math.sqrt(var)
        srt = sorted(scores)
        med = srt[n // 2]
        return {"mean": round(mu,4), "std": round(sd,4), "median": round(med,4),
                "min": round(min(scores),4), "max": round(max(scores),4), "n": n}

    distributions = {k: {"scores": [round(s,4) for s in v], "stats": stats(v)}
                     for k, v in scenarios.items()}

    # ROC: benign vs. random
    roc = compute_roc(scenarios["benign"], scenarios["random"])

    # ROC: benign+noise vs. partial_50 (harder separation)
    roc_noisy = compute_roc(scenarios["noisy_05pct"], scenarios["partial_50"])

    # Metrics at 85% threshold
    thresh = 0.85
    metrics_at_85 = {}
    for name, scores in scenarios.items():
        accepted = sum(1 for s in scores if s >= thresh)
        metrics_at_85[name] = {
            "accepted": accepted,
            "rejected": len(scores) - accepted,
            "accept_rate": round(accepted / len(scores), 4),
        }

    # Noise tolerance: FNR vs. noise level
    noise_levels = [0.00, 0.02, 0.05, 0.08, 0.10, 0.12, 0.15, 0.20, 0.25]
    noise_tolerance = []
    for nl in noise_levels:
        sc = simulate_scenario("noisy_05", 200) if nl == 0.05 else [
            compute_confidence(
                tok := [(random.choice(['+','x']), random.randint(0,1)) for _ in range(16)],
                add_noise(tok, nl)
            ) for _ in range(200)
        ]
        fnr = sum(1 for s in sc if s < thresh) / len(sc)
        noise_tolerance.append({"noise_level": nl, "fnr": round(fnr, 4),
                                 "mean_conf": round(sum(sc)/len(sc), 4)})

    return {
        "distributions": distributions,
        "roc_benign_vs_random":    roc,
        "roc_noisy_vs_partial50":  roc_noisy,
        "metrics_at_threshold_85": metrics_at_85,
        "noise_tolerance_curve":   noise_tolerance,
        "threshold": thresh,
        "n_samples": n_samples,
    }
