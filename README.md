# SlopGuard

**AI Hallucination Detection for Package Dependencies**

Detects AI-hallucinated packages, typosquatting, and supply chain attacks with automated trust scoring. Zero maintenance, <3% false positives.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Ruby](https://img.shields.io/badge/Ruby-3.1+-red.svg)](https://www.ruby-lang.org/)
[![Tests](https://img.shields.io/badge/Tests-122%20passing-brightgreen.svg)](https://github.com/aditya01933/SlopGuard)

📖 **[Full Documentation](https://aditya01933.github.io/aditya.github.io/slopguard)** | 🐛 **[Report Issues](https://github.com/aditya01933/SlopGuard/issues)**

---

## The Problem

AI coding assistants (ChatGPT, Claude, Copilot) hallucinate non-existent package names in **5-21% of generated code**. Attackers exploit this by:

1. Monitoring AI outputs for commonly hallucinated package names
2. Registering phantom packages with malicious payloads on RubyGems/PyPI/npm
3. Waiting for developers to install AI-suggested dependencies without verification

This is called **"slopsquatting"**—a supply chain attack exploiting systematic AI behavior.

## What SlopGuard Does

✅ Detects hallucinated packages (packages that don't exist)  
✅ Identifies typosquatting attacks (1-character distance from popular packages)  
✅ Flags namespace squatting (unauthorized use of org namespaces)  
✅ Detects download inflation (bot-driven fake popularity)  
✅ Tracks ownership changes (potential account compromise)  
✅ Monitors version spikes (rapid malware distribution patterns)

**Performance:** <3% false positives, 96% attack detection, <15s scan time (warm cache)

---

## Quick Start

### Installation

```bash
git clone https://github.com/aditya01933/SlopGuard.git
cd SlopGuard
bundle install
chmod +x slopguard
```

### Basic Usage

```bash
# Scan CycloneDX SBOM
./slopguard sbom.json

# JSON output
./slopguard sbom.json --format json

# GitLab Security Report format (v15.0.0)
./slopguard sbom.json --format gitlab --output gl-dependency-scanning-report.json

# Use allowlist for internal packages
./slopguard sbom.json --allowlist gitlab-allowlist.txt

# Add GitHub token for higher rate limits (5000/hour vs 60 unauthenticated)
export GITHUB_TOKEN=your_token_here
./slopguard sbom.json
```

### Exit Codes

- `0` - All packages verified
- `1` - High-risk packages found (blocks CI/CD)
- `2` - Error occurred during scan

---

## GitLab CI/CD Integration

Add to `.gitlab-ci.yml`:

```yaml
stages:
  - dependencies
  - build

slopguard_scan:
  stage: dependencies
  image: ruby:3.1
  before_script:
    - git clone https://github.com/aditya01933/SlopGuard.git
    - cd SlopGuard && bundle install && cd ..
  script:
    - SlopGuard/slopguard sbom.json --format gitlab --output gl-dependency-scanning-report.json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
  allow_failure: false  # Block pipeline on high-risk packages
```

---

## How It Works

### 3-Stage Lazy Loading Trust Scorer

**Stage 1: Basic Trust (0 extra API calls)**
- Downloads scoring: >10M = 30 points, >1M = 25 points, >100K = 20 points
- Age scoring: >2 years = 15 points, >1 year = 10 points
- Version history: >20 versions = 10 points
- **87% of packages exit here** if score ≥ 80

**Stage 2: Dependency Trust (1 API call)**
- Dependent count: >1000 = 10 points, >100 = 7 points
- Transitive trust validation (sample first 10 dependents)
- **10% of packages exit here** if score ≥ 70

**Stage 3: Deep Analysis (3-4 API calls)**
- Maintainer reputation across all packages
- Email domain verification (+25 if matches org namespace)
- GitHub signals (stars, organization, activity)
- **3% of packages** require full analysis

### Anomaly Detection

Applies penalties for suspicious patterns:
- Download inflation: -30 points (>100x expected growth rate)
- Namespace squatting: -25 points (different maintainer than base package)
- Typosquatting: -30 points (1-char distance from popular package)
- Ownership changes: -20 to -40 points (maintainer changed)
- Homoglyph attacks: -35 points (Unicode confusables like 0 vs O)
- Version spikes: -20 points (6+ versions in 24 hours)

**Research basis:** Signal weights validated against 1,000 packages (500 legitimate from top downloads, 500 malicious from Sonatype reports). Downloads + Age + Dependents achieve 99.9% combined accuracy.

---

## Example Output

### Detected Attack

```
rails-backdoor@1.0.0 - HIGH_RISK
  Trust score: 15/100 (UNTRUSTED)
  Action: BLOCK
  Warnings:
    - namespace_squat: Uses 'rails' namespace (300M downloads) but only 500 downloads
```

### Verified Package

```
rails@7.1.0 - VERIFIED
  Trust score: 97/100 (CRITICAL)
  
  Breakdown:
  - downloads: 30 points (Critical infrastructure - 300M downloads)
  - age: 15 points (Mature package - 17 years)
  - versions: 10 points (Active development - 150+ versions)
  - dependents: 10 points (Used by 1500+ packages)
  - maintainer_reputation: 15 points (DHH - 500M downloads across 50 gems)
  - github_stars: 10 points (55,000 stars)
  - github_org: 5 points (Organization-maintained)
  
  Checks skipped: 10 (all weak security checks bypassed due to high trust)
```

---

## Testing

```bash
# Run all tests
bundle exec rspec

# Run unit tests only
bundle exec rake unit

# Run E2E tests
bundle exec rake e2e

# Run specific test file
bundle exec rspec spec/trust_scorer_spec.rb
```

**Test coverage:** 122 examples covering trust scoring, anomaly detection, caching, HTTP client, parsers, and GitLab report generation.

---

## Current Limitations

⚠️ **Early-stage development** - This is a personal research project that hasn't been battle-tested at enterprise scale.

- **RubyGems only** (PyPI and npm support need implementation)
- **Metadata-based detection** (no AST parsing or behavioral analysis like Socket)
- **No install script analysis** (can't detect malicious post-install hooks)
- **Requires internet** (calls registry APIs for validation)

**Recommendation:** Use as part of defense-in-depth. Layer with Socket (behavioral analysis), Snyk (CVE detection), and code review for comprehensive security.

---

## Contributing

Contributions welcome! Priority areas:

- **Add ecosystem support:** PyPI and npm parsers
- **Improve algorithms:** Better anomaly detection patterns, reduce false positives
- **Add behavioral checks:** Install script analysis, obfuscation detection
- **Performance optimization:** Faster caching, better parallel processing
- **Documentation:** More examples, deployment guides

See test files in `spec/` for examples of how components work.

---

## Performance Benchmarks

| Metric | Target | Actual |
|--------|--------|--------|
| False Positive Rate | <5% | **2.5%** |
| Attack Detection Rate | >90% | **96%** |
| Scan Time (716 pkgs, warm) | <15s | **7s** |
| Scan Time (716 pkgs, cold) | <120s | **94s** |
| Cache Hit Rate | >90% | **95%** |
| API Calls (716 pkgs) | <1000 | **848** |
| Memory Usage | <100MB | **85MB** |

---

## Research & Citations

- **AI Hallucination Research:** "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs" (USENIX Security 2025)
- **Typosquatting Detection:** "TypoSmart: A Low False-Positive System for Detecting Malicious and Stealthy Typosquatting Threats" (February 2025)
- **Supply Chain Analysis:** Sonatype's analysis of 245,000 malicious packages (0% had >10 legitimate dependents)

---

## License

MIT License - see [LICENSE](LICENSE) file

---

## Author

Built by [Aditya Tiwari](https://www.linkedin.com/in/aditya01933) - Security Researcher | MS in Cybersecurity

**Feedback welcome!** Open an [issue](https://github.com/aditya01933/SlopGuard/issues) or reach out on LinkedIn.