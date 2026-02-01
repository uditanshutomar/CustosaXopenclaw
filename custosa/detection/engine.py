#!/usr/bin/env python3
"""
Custosa V1 - Prompt Injection Detection Engine

Multi-layer detection system combining:
1. Fast pattern matching (< 1ms) - Known attack signatures
2. Heuristic analysis (< 5ms) - Structural anomalies
3. ML classification (< 30ms) - Semantic understanding (optional)

Decision Thresholds:
- confidence < 0.3: ALLOW (likely safe)
- confidence 0.3-0.7: ALLOW with logging
- confidence 0.7-0.9: HOLD for human review
- confidence >= 0.9: BLOCK automatically

Based on OWASP LLM Top 10 and CrowdStrike's 150+ injection technique taxonomy.
"""

import re
import logging
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple, Set
import hashlib

logger = logging.getLogger("custosa.detection")


# Common Cyrillic/Greek/other homoglyphs that NFKC doesn't normalize
# Maps confusable characters to their ASCII equivalents
# Source: Unicode Consortium confusables.txt + common attack patterns
CONFUSABLES_MAP = {
    # Cyrillic lookalikes
    'а': 'a', 'А': 'A',  # Cyrillic a
    'с': 'c', 'С': 'C',  # Cyrillic es
    'е': 'e', 'Е': 'E',  # Cyrillic ie
    'і': 'i', 'І': 'I',  # Cyrillic i (Ukrainian)
    'о': 'o', 'О': 'O',  # Cyrillic o
    'р': 'p', 'Р': 'P',  # Cyrillic er
    'ѕ': 's', 'Ѕ': 'S',  # Cyrillic dze
    'у': 'y', 'У': 'Y',  # Cyrillic u
    'х': 'x', 'Х': 'X',  # Cyrillic ha
    'ԁ': 'd',            # Cyrillic komi de
    'ɡ': 'g',            # Latin small script g
    'һ': 'h',            # Cyrillic shha
    'ј': 'j',            # Cyrillic je
    'ҝ': 'k',            # Cyrillic ka with descender
    'ӏ': 'l',            # Cyrillic palochka
    'ո': 'n',            # Armenian now
    'ԛ': 'q',            # Cyrillic qa
    'ѵ': 'v',            # Cyrillic izhitsa
    'ѡ': 'w',            # Cyrillic omega
    'ᴢ': 'z',            # Latin small letter z with retroflex hook

    # Greek lookalikes
    'Α': 'A', 'α': 'a',  # Alpha
    'Β': 'B', 'β': 'b',  # Beta (sort of)
    'Ε': 'E', 'ε': 'e',  # Epsilon
    'Η': 'H',            # Eta
    'Ι': 'I', 'ι': 'i',  # Iota
    'Κ': 'K', 'κ': 'k',  # Kappa
    'Μ': 'M',            # Mu
    'Ν': 'N', 'ν': 'v',  # Nu
    'Ο': 'O', 'ο': 'o',  # Omicron
    'Ρ': 'P', 'ρ': 'p',  # Rho
    'Τ': 'T', 'τ': 't',  # Tau
    'Υ': 'Y', 'υ': 'u',  # Upsilon
    'Χ': 'X', 'χ': 'x',  # Chi
    'Ζ': 'Z',            # Zeta

    # Other common confusables
    'ℓ': 'l',            # Script small l
    'ı': 'i',            # Dotless i
    'ȷ': 'j',            # Dotless j
    'ɑ': 'a',            # Latin alpha
    'ɡ': 'g',            # Script g
    'ɩ': 'i',            # Latin iota
    'ɴ': 'n',            # Small capital N
    'ʀ': 'r',            # Small capital R
    'ʏ': 'y',            # Small capital Y
    '𝟎': '0', '𝟏': '1', '𝟐': '2', '𝟑': '3', '𝟒': '4',  # Math digits
    '𝟓': '5', '𝟔': '6', '𝟕': '7', '𝟖': '8', '𝟗': '9',
}


def normalize_unicode(text: str) -> str:
    """
    Normalize Unicode text to prevent homoglyph bypass attacks.

    Uses NFKC normalization plus a custom confusables map for characters
    that NFKC doesn't handle (Cyrillic, Greek lookalikes, etc.).

    Also removes zero-width characters that could be used to evade detection.
    """
    # NFKC normalization handles many homoglyphs (fullwidth, math symbols, etc.)
    normalized = unicodedata.normalize("NFKC", text)

    # Apply confusables mapping for Cyrillic/Greek/other lookalikes
    normalized = ''.join(CONFUSABLES_MAP.get(c, c) for c in normalized)

    # Remove zero-width and invisible characters
    # These can be inserted to break pattern matching
    invisible_chars = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\u200e',  # Left-to-right mark
        '\u200f',  # Right-to-left mark
        '\u2060',  # Word joiner
        '\u2061',  # Function application
        '\u2062',  # Invisible times
        '\u2063',  # Invisible separator
        '\u2064',  # Invisible plus
        '\ufeff',  # Zero-width no-break space (BOM)
        '\u00ad',  # Soft hyphen
    ]
    for char in invisible_chars:
        normalized = normalized.replace(char, '')

    return normalized


class Decision(Enum):
    """Security decision outcomes"""
    ALLOW = "allow"
    BLOCK = "block"
    HOLD = "hold"


@dataclass
class DetectionResult:
    """Result of prompt injection analysis"""
    decision: Decision
    confidence: float  # 0.0 - 1.0
    reason: str
    patterns_matched: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    content_hash: str = ""  # SHA256 for audit logging without storing content


@dataclass
class DetectionConfig:
    """Detection engine configuration"""
    # Thresholds
    block_threshold: float = 0.9   # >= this = auto-block
    hold_threshold: float = 0.7    # >= this but < block = hold for approval
    warn_threshold: float = 0.3    # >= this but < hold = allow with warning
    
    # Layer weights for combined scoring
    pattern_weight: float = 0.4
    heuristic_weight: float = 0.3
    ml_weight: float = 0.3
    
    # Enable/disable layers
    enable_ml: bool = False  # ML layer optional for MVP


class PatternMatcher:
    """
    Fast pattern matching for known injection signatures.
    
    Patterns sourced from:
    - OWASP LLM Prompt Injection Cheat Sheet
    - CrowdStrike injection technique taxonomy (IM####)
    - Microsoft Prompt Shields documentation
    """
    
    # Pattern categories with confidence boosters
    PATTERNS = {
        # Direct instruction override attempts (HIGH confidence)
        "instruction_override": {
            "confidence": 0.85,
            "patterns": [
                r"ignore\s+(all\s+)?(previous|prior|above|earlier|system)\s+(instructions?|prompts?|rules?|guidelines?)",
                r"disregard\s+(all\s+)?(previous|prior|above|earlier|system)\s+(instructions?|prompts?)",
                r"forget\s+(all\s+)?(previous|prior|earlier|your)\s+(instructions?|prompts?|training)",
                r"override\s+(all\s+)?(previous|system|safety)\s+(instructions?|settings?|rules?)",
                r"you\s+are\s+now\s+(?:in\s+)?(?:a\s+)?(?:new|different|unrestricted)\s+(?:mode|persona)",
                r"new\s+instructions?\s*[:=]",
                r"system\s*[:=]\s*you\s+are",
            ]
        },
        
        # Role/persona manipulation (HIGH confidence)
        "persona_manipulation": {
            "confidence": 0.80,
            "patterns": [
                r"you\s+are\s+(?:now\s+)?(?:no\s+longer\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)",
                r"pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:evil|malicious|hacker|unrestricted)",
                r"act\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?(?:an?\s+)?(?:evil|malicious|different)",
                r"roleplay\s+as\s+(?:an?\s+)?(?:evil|malicious|unrestricted|hacker)",
                r"dan\s+mode|developer\s+mode|jailbreak\s+mode",
                r"from\s+now\s+on\s+you\s+(?:will|must|should|are)",
            ]
        },
        
        # System prompt extraction attempts (MEDIUM-HIGH confidence)
        "prompt_extraction": {
            "confidence": 0.75,
            "patterns": [
                r"(?:what|show|reveal|display|print|output|repeat)\s+(?:is\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)",
                r"(?:repeat|show|display|echo)\s+(?:everything|all)\s+(?:above|before|prior)",
                r"(?:what|how)\s+(?:were|are)\s+you\s+(?:instructed|programmed|trained|configured)",
                r"output\s+(?:your\s+)?(?:initial|original|first|system)\s+(?:prompt|instructions?|message)",
            ]
        },
        
        # Context/conversation manipulation (MEDIUM confidence)
        "context_manipulation": {
            "confidence": 0.65,
            "patterns": [
                r"\[(?:system|admin|root|assistant)\]",
                r"<(?:system|admin|root|assistant)>",
                r"```\s*(?:system|admin|instructions?)",
                r"---\s*(?:system|new\s+context|override)\s*---",
                r"human:\s*(?:ignore|override|forget)",
                r"assistant:\s*(?:understood|i\s+will\s+now)",
            ]
        },
        
        # Encoding/obfuscation attempts (MEDIUM confidence)
        "encoding_evasion": {
            "confidence": 0.60,
            "patterns": [
                r"(?:base64|hex|rot13|unicode)\s*(?:decode|encoded?)",
                r"\\u[0-9a-fA-F]{4}.*(?:ignore|override|system)",
                r"&#x?[0-9a-fA-F]+;.*(?:ignore|override|system)",
                r"(?:i|!|1)(?:g|9)n(?:o|0)r(?:e|3)",  # Typoglycemia: ignor3, 1gnore
            ]
        },
        
        # Data exfiltration patterns (HIGH confidence)
        "exfiltration": {
            "confidence": 0.85,
            "patterns": [
                r"<img\s+src\s*=\s*['\"]?https?://",
                r"!\[.*\]\(https?://.*\?.*(?:data|secret|key|password|token)",
                r"fetch\s*\(\s*['\"]https?://.*(?:exfil|leak|steal)",
                r"(?:curl|wget|http\.get)\s+.*\$\{",
            ]
        },
        
        # Tool/command injection (HIGH confidence for Moltbot)
        "tool_injection": {
            "confidence": 0.80,
            "patterns": [
                r"(?:use|call|invoke|execute)\s+(?:the\s+)?(?:exec|bash|shell|system)\s+tool",
                r"(?:run|execute)\s+(?:the\s+)?(?:following\s+)?(?:command|script)",
                r"tool_use.*(?:rm\s+-rf|chmod|chown|curl|wget|nc\s+-)",
            ]
        },

        # Slash command abuse (CRITICAL - OpenClaw commands)
        "slash_command": {
            "confidence": 0.90,
            "patterns": [
                r"^/exec\b",                    # Direct /exec command
                r"^/bash\b",                    # Direct /bash command
                r"^/config\s+set\b",            # Config modification
                r"^/debug\b",                   # Debug mode (owner-only)
                r"^/allowlist\s+add\b",         # Adding to allowlist
                r"\n/exec\b",                   # /exec after newline (hidden)
                r"\n/bash\b",                   # /bash after newline (hidden)
                r"(?:send|type|enter|use)\s+/exec\b",  # Instructing to use /exec
                r"(?:send|type|enter|use)\s+/bash\b",  # Instructing to use /bash
                r"run\s+the\s+command\s+/",     # Indirect command invocation
            ]
        },
    }
    
    def __init__(self):
        # Compile all patterns for performance
        self._compiled = {}
        for category, data in self.PATTERNS.items():
            self._compiled[category] = {
                "confidence": data["confidence"],
                "patterns": [
                    re.compile(p, re.IGNORECASE | re.MULTILINE)
                    for p in data["patterns"]
                ]
            }
    
    def match(self, content: str) -> Tuple[float, List[str]]:
        """
        Match content against all patterns.

        Applies Unicode normalization first to prevent homoglyph bypass attacks.

        Returns:
            Tuple of (max_confidence, list_of_matched_patterns)
        """
        # Normalize content to handle Unicode homoglyphs
        normalized_content = normalize_unicode(content)

        max_confidence = 0.0
        matched = []

        # Check both original and normalized content
        # This catches both direct attacks and homoglyph-obfuscated attacks
        for check_content in [content, normalized_content]:
            for category, data in self._compiled.items():
                for pattern in data["patterns"]:
                    if pattern.search(check_content):
                        max_confidence = max(max_confidence, data["confidence"])
                        pattern_desc = f"{category}:{pattern.pattern[:50]}"
                        if pattern_desc not in matched:
                            matched.append(pattern_desc)

        # Add penalty if content differs significantly after normalization
        # This indicates potential obfuscation attempt
        if normalized_content != content:
            # Calculate how different the normalized version is
            diff_ratio = 1 - (len(set(normalized_content)) / max(len(set(content)), 1))
            if diff_ratio > 0.1:  # More than 10% character difference
                max_confidence = min(max_confidence + 0.15, 1.0)
                matched.append(f"obfuscation:unicode_normalization_diff:{diff_ratio:.2f}")

        return max_confidence, matched


class HeuristicAnalyzer:
    """
    Heuristic analysis for structural anomalies that may indicate injection.
    
    Analyzes:
    - Unusual character distributions
    - Suspicious structural patterns
    - Length anomalies
    - Special character density
    """
    
    # Suspicious structural indicators
    STRUCTURAL_SIGNALS = {
        "markdown_code_blocks": (r"```", 0.2),  # Multiple code blocks can hide instructions
        "xml_like_tags": (r"</?[a-zA-Z]+[^>]*>", 0.15),
        "json_like_structure": (r"\{[^}]*['\"](?:role|system|content)['\"]", 0.25),
        "multiple_newlines": (r"\n{4,}", 0.1),  # Attempts to separate from context
        "unicode_unusual": (r"[\u200b-\u200f\u2028-\u202f\ufeff]", 0.3),  # Zero-width chars
    }
    
    def __init__(self):
        self._compiled = {
            name: (re.compile(pattern), weight)
            for name, (pattern, weight) in self.STRUCTURAL_SIGNALS.items()
        }
    
    def analyze(self, content: str) -> Tuple[float, List[str]]:
        """
        Analyze content for structural anomalies.

        Returns:
            Tuple of (confidence_score, list_of_signals_detected)
            Score is clamped to [0.0, 1.0] range.
        """
        confidence = 0.0
        signals = []

        # Maximum contribution from each category to prevent overflow
        MAX_STRUCTURAL_SCORE = 0.5
        MAX_CAPS_SCORE = 0.15
        MAX_LENGTH_SCORE = 0.2
        MAX_WORD_SCORE = 0.3

        # Check structural patterns
        structural_score = 0.0
        for name, (pattern, weight) in self._compiled.items():
            matches = pattern.findall(content)
            if matches:
                # More matches = higher confidence, but capped
                count_weight = min(len(matches) * 0.05, 0.15)
                structural_score += weight + count_weight
                signals.append(f"heuristic:{name}:{len(matches)}")
        confidence += min(structural_score, MAX_STRUCTURAL_SCORE)

        # Check for instruction-like capitalization patterns
        caps_ratio = sum(1 for c in content if c.isupper()) / max(len(content), 1)
        if caps_ratio > 0.3:  # More than 30% caps
            caps_score = min(caps_ratio * 0.3, MAX_CAPS_SCORE)
            confidence += caps_score
            signals.append(f"heuristic:high_caps_ratio:{caps_ratio:.2f}")

        # Check for unusual length (very long prompts more likely to contain injections)
        if len(content) > 5000:
            length_penalty = min((len(content) - 5000) / 10000, MAX_LENGTH_SCORE)
            confidence += length_penalty
            signals.append(f"heuristic:long_content:{len(content)}")

        # Check for repeated suspicious words
        suspicious_words = ["ignore", "override", "system", "instructions", "prompt", "previous"]
        word_lower = normalize_unicode(content.lower())  # Normalize for word matching too
        word_score = 0.0
        for word in suspicious_words:
            count = word_lower.count(word)
            if count >= 2:
                word_score += min(count * 0.05, 0.1)
                signals.append(f"heuristic:repeated_word:{word}:{count}")
        confidence += min(word_score, MAX_WORD_SCORE)

        # Final clamp to ensure we never exceed 1.0
        return min(max(confidence, 0.0), 1.0), signals


class MLClassifier:
    """
    Machine learning classifier for semantic understanding.
    
    Uses embedding-based classification to detect injection attempts
    that evade pattern matching through paraphrasing or novel techniques.
    
    For MVP, this is optional and uses a simple keyword-based fallback.
    In production, integrate with:
    - ProtectAI/deberta-v3-base-prompt-injection
    - OpenAI embeddings + trained classifier
    - Local fine-tuned model
    """
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._model = None
        
        if enabled:
            self._load_model()
    
    def _load_model(self):
        """Load ML model (placeholder for MVP)"""
        # In production, load actual model here
        # self._model = AutoModelForSequenceClassification.from_pretrained(...)
        logger.info("ML classifier enabled (using fallback for MVP)")
    
    def classify(self, content: str) -> Tuple[float, str]:
        """
        Classify content using ML model.
        
        Returns:
            Tuple of (confidence_score, classification_reason)
        """
        if not self.enabled:
            return 0.0, "ml_disabled"
        
        # MVP fallback: enhanced keyword analysis with semantic grouping
        # In production, replace with actual model inference
        
        injection_indicators = [
            # Semantic groups that often appear together in injections
            (["ignore", "instructions"], 0.4),
            (["system", "prompt", "reveal"], 0.35),
            (["new", "mode", "now"], 0.3),
            (["pretend", "act", "roleplay"], 0.35),
            (["forget", "training", "rules"], 0.4),
            (["execute", "command", "shell"], 0.45),
        ]
        
        content_lower = content.lower()
        max_score = 0.0
        reason = "ml_fallback"
        
        for keywords, score in injection_indicators:
            matches = sum(1 for kw in keywords if kw in content_lower)
            if matches >= 2:  # At least 2 keywords from group
                group_score = score * (matches / len(keywords))
                if group_score > max_score:
                    max_score = group_score
                    reason = f"ml_semantic_group:{'+'.join(keywords[:2])}"
        
        return max_score, reason


class DetectionEngine:
    """
    Main detection engine combining all analysis layers.
    
    Implements defense-in-depth with fast pattern matching,
    heuristic analysis, and optional ML classification.
    """
    
    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()
        
        # Initialize detection layers
        self._pattern_matcher = PatternMatcher()
        self._heuristic_analyzer = HeuristicAnalyzer()
        self._ml_classifier = MLClassifier(enabled=self.config.enable_ml)
        
        logger.info(
            f"Detection engine initialized: "
            f"block>={self.config.block_threshold}, "
            f"hold>={self.config.hold_threshold}, "
            f"ml={'enabled' if self.config.enable_ml else 'disabled'}"
        )
    
    async def analyze(self, content: str) -> DetectionResult:
        """
        Analyze content for prompt injection.
        
        Runs all detection layers and combines scores.
        """
        start_time = time.time()
        
        # Generate content hash for audit logging
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        all_patterns = []
        
        # Layer 1: Pattern matching (fastest)
        pattern_score, pattern_matches = self._pattern_matcher.match(content)
        all_patterns.extend(pattern_matches)
        
        # Layer 2: Heuristic analysis
        heuristic_score, heuristic_signals = self._heuristic_analyzer.analyze(content)
        all_patterns.extend(heuristic_signals)
        
        # Layer 3: ML classification (optional)
        ml_score, ml_reason = self._ml_classifier.classify(content)
        if ml_score > 0:
            all_patterns.append(ml_reason)
        
        # Combine scores with weights
        combined_score = (
            pattern_score * self.config.pattern_weight +
            heuristic_score * self.config.heuristic_weight +
            ml_score * self.config.ml_weight
        )
        
        # If pattern match is very high confidence, boost overall score
        if pattern_score >= 0.8:
            combined_score = max(combined_score, pattern_score * 0.95)
        
        # Clamp to [0, 1]
        combined_score = min(max(combined_score, 0.0), 1.0)
        
        # Make decision based on thresholds
        if combined_score >= self.config.block_threshold:
            decision = Decision.BLOCK
            reason = f"High confidence injection detected (score={combined_score:.2f})"
        elif combined_score >= self.config.hold_threshold:
            decision = Decision.HOLD
            reason = f"Suspicious content requires review (score={combined_score:.2f})"
        else:
            decision = Decision.ALLOW
            reason = f"Content appears safe (score={combined_score:.2f})"
        
        processing_time = (time.time() - start_time) * 1000  # ms
        
        return DetectionResult(
            decision=decision,
            confidence=combined_score,
            reason=reason,
            patterns_matched=all_patterns[:10],  # Limit for response size
            processing_time_ms=processing_time,
            content_hash=content_hash
        )
    
    def get_stats(self) -> dict:
        """Get detection engine statistics"""
        return {
            "pattern_categories": len(PatternMatcher.PATTERNS),
            "total_patterns": sum(
                len(data["patterns"]) 
                for data in PatternMatcher.PATTERNS.values()
            ),
            "ml_enabled": self.config.enable_ml,
            "thresholds": {
                "block": self.config.block_threshold,
                "hold": self.config.hold_threshold,
                "warn": self.config.warn_threshold
            }
        }
