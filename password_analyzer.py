
import re
import string
from dataclasses import dataclass, field
from enum import Enum


class StrengthLevel(Enum):
    WEAK = "Weak"
    FAIR = "Fair"
    GOOD = "Good"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"


@dataclass
class CriterionResult:
    name: str
    passed: bool
    message: str


@dataclass
class AnalysisResult:
    score: int
    max_score: int
    strength: StrengthLevel
    criteria: list[CriterionResult] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    length: int = 0


COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "shadow", "123123",
    "654321", "superman", "qazwsx", "password1", "admin", "welcome",
}


def _has_uppercase(password: str) -> bool:
    return any(c.isupper() for c in password)


def _has_lowercase(password: str) -> bool:
    return any(c.islower() for c in password)


def _has_digit(password: str) -> bool:
    return any(c.isdigit() for c in password)


def _has_special(password: str) -> bool:
    return any(c in string.punctuation for c in password)


def _has_repeated_chars(password: str, threshold: int = 3) -> bool:
    if len(password) < threshold:
        return False
    for i in range(len(password) - threshold + 1):
        if len(set(password[i : i + threshold])) == 1:
            return True
    return False


def _has_sequential_chars(password: str, min_len: int = 4) -> bool:
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]
    lower = password.lower()
    for seq in sequences:
        for i in range(len(seq) - min_len + 1):
            chunk = seq[i : i + min_len]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def analyze_password(password: str) -> AnalysisResult:
    """Analyze a password and return strength score, criteria, and recommendations."""
    criteria: list[CriterionResult] = []
    recommendations: list[str] = []
    score = 0
    max_score = 100

    length = len(password)

    if length == 0:
        return AnalysisResult(
            score=0,
            max_score=max_score,
            strength=StrengthLevel.WEAK,
            criteria=[
                CriterionResult("Length", False, "Password is empty"),
            ],
            recommendations=["Enter a password to analyze."],
            length=0,
        )

    # Length scoring (max 30 points)
    if length >= 16:
        length_score = 30
        criteria.append(CriterionResult("Length (16+ characters)", True, f"{length} characters"))
    elif length >= 12:
        length_score = 22
        criteria.append(CriterionResult("Length (12+ characters)", True, f"{length} characters"))
        recommendations.append("Use at least 16 characters for maximum security.")
    elif length >= 8:
        length_score = 14
        criteria.append(CriterionResult("Length (8+ characters)", True, f"{length} characters"))
        recommendations.append("Increase password length to at least 12 characters.")
    else:
        length_score = max(0, length * 2)
        criteria.append(CriterionResult("Length (8+ characters)", False, f"Only {length} characters"))
        recommendations.append("Use at least 8 characters; 12+ is recommended.")

    score += length_score

    # Character type checks (15 points each, max 60)
    checks = [
        ("Uppercase letters (A-Z)", _has_uppercase, "Add uppercase letters (A-Z)."),
        ("Lowercase letters (a-z)", _has_lowercase, "Add lowercase letters (a-z)."),
        ("Numeric characters (0-9)", _has_digit, "Add numbers (0-9)."),
        ("Special symbols (!@#$...)", _has_special, "Add special symbols (!@#$%^&*)."),
    ]

    for name, check_fn, rec in checks:
        passed = check_fn(password)
        criteria.append(
            CriterionResult(name, passed, "Present" if passed else "Missing")
        )
        if passed:
            score += 15
        else:
            recommendations.append(rec)

    # Bonus checks (max 10 points)
    unique_ratio = len(set(password)) / length
    if unique_ratio >= 0.7:
        score += 5
        criteria.append(CriterionResult("Character variety", True, "Good mix of characters"))
    else:
        criteria.append(CriterionResult("Character variety", False, "Too many repeated characters"))
        recommendations.append("Avoid repeating the same characters.")

    if not _has_repeated_chars(password):
        score += 3
    else:
        recommendations.append("Avoid consecutive repeated characters (e.g., 'aaa').")

    if not _has_sequential_chars(password):
        score += 2
    else:
        recommendations.append("Avoid sequential patterns (e.g., '1234', 'abcd').")

    # Penalties
    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 25)
        criteria.append(CriterionResult("Common password check", False, "Password is commonly used"))
        recommendations.insert(0, "Avoid common passwords — choose something unique.")
    else:
        criteria.append(CriterionResult("Common password check", True, "Not a known weak password"))

    if re.fullmatch(r"[a-zA-Z]+", password):
        score = max(0, score - 10)
        recommendations.append("Do not use only letters — mix character types.")

    if re.fullmatch(r"\d+", password):
        score = max(0, score - 15)
        recommendations.append("Do not use only numbers.")

    score = min(score, max_score)

    strength = _score_to_strength(score)

    if strength in (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG):
        recommendations.append("Great job! Consider using a password manager to store it securely.")

    # Deduplicate recommendations while preserving order
    seen = set()
    unique_recs = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recs.append(rec)

    return AnalysisResult(
        score=score,
        max_score=max_score,
        strength=strength,
        criteria=criteria,
        recommendations=unique_recs,
        length=length,
    )


def _score_to_strength(score: int) -> StrengthLevel:
    if score >= 85:
        return StrengthLevel.VERY_STRONG
    if score >= 70:
        return StrengthLevel.STRONG
    if score >= 50:
        return StrengthLevel.GOOD
    if score >= 30:
        return StrengthLevel.FAIR
    return StrengthLevel.WEAK


STRENGTH_COLORS = {
    StrengthLevel.WEAK: "#f87171",
    StrengthLevel.FAIR: "#fb923c",
    StrengthLevel.GOOD: "#fbbf24",
    StrengthLevel.STRONG: "#34d399",
    StrengthLevel.VERY_STRONG: "#14b8a6",
}
