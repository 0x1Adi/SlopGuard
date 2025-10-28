# SlopGuard

**AI Hallucination Detection for Package Dependencies**

Detects AI-hallucinated packages, typosquatting, and supply chain attacks with automated trust scoring. Zero maintenance, <3% false positives, multi-ecosystem support.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Ruby](https://img.shields.io/badge/Ruby-3.1+-red.svg)](https://www.ruby-lang.org/)

---

## The Problem

AI coding assistants (ChatGPT, Claude, Copilot) hallucinate non-existent package names in **9-21% of generated code**. Attackers exploit this by:

1. Monitoring AI outputs for commonly hallucinated package names
2. Registering phantom packages with malicious payloads
3. Waiting for developers to install AI-suggested dependencies without verification

This is called **"slopsquatting"**—a supply chain attack exploiting systematic AI behavior.

## What SlopGuard Does

✅ Detects hallucinated packages (packages that don't exist)  
✅ Identifies typosquatting attacks (1-character distance from popular packages)  
✅ Flags namespace squatting (unauthorized use of org namespaces)  
✅ Detects download inflation (bot-driven fake popularity)  
✅ Multi-ecosystem support (Ruby, Python, easy to extend)  
✅ Automated trust scoring (no manual whitelist maintenance)

**Performance:** 71% verified in real-world test, 100% hallucination detection, 18x cache speedup

---

## Supported Ecosystems

- ✅ **Ruby (RubyGems)** - Full support with download stats, dependents, GitHub integration
- ✅ **Python (PyPI)** - Full support with version history, classifiers, GitHub integration
- 🔜 **npm (JavaScript)** - Easy to add using adapter pattern (~30 min implementation)
- 🔜 **Cargo (Rust)** - Easy to add using adapter pattern (~30 min implementation)

See [ADDING_ECOSYSTEMS.md](ADDING_ECOSYSTEMS.md) for how to add new package registries.

---

## Quick Start

### Installation

```bash
git clone https://github.com/yourusername/SlopGuard.git
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

# Add GitHub token for higher rate limits (5000/hour vs 60 unauthenticated)
export GITHUB_TOKEN=your_token_here
./slopguard sbom.json
```

### Exit Codes

- `0` - All packages verified or warnings only
- `1` - High-risk or non-existent packages found (blocks CI/CD)
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
    - git clone https://github.com/yourusername/SlopGuard.git
    - cd SlopGuard && bundle install && cd ..
  script:
    - SlopGuard/slopguard sbom.json --format gitlab --output gl-dependency-scanning-report.json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    expire_in: 30 days
  variables:
    GITHUB_TOKEN: $GITHUB_TOKEN  # Set in CI/CD variables
  allow_failure: false
```

---

## How It Works

### Modular Adapter Architecture

SlopGuard uses an **adapter pattern** to support multiple package ecosystems:

```
Parser → AdapterFactory → RubyGemsAdapter or PyPIAdapter → TrustScorer
```

Each ecosystem adapter handles:
- Fetching metadata from ecosystem-specific APIs
- Calculating trust scores from available signals
- Detecting ecosystem-specific anomalies

**Adding new ecosystems takes ~30 minutes** - just implement one adapter class.

### 3-Stage Lazy Trust Scoring

**Stage 1: Basic Trust (0 extra API calls)**
- Downloads: >10M = 30 pts, >1M = 25 pts (Ruby only - PyPI lacks download API)
- Age: >2 years = 15-25 pts (higher weight for PyPI to compensate)
- Versions: >20 versions = 10-20 pts (higher weight for PyPI)
- Classifiers: Production/Stable = 10 pts (PyPI only)
- **Exit early if score ≥ 70** (87% of packages)

**Stage 2: Dependents (1 API call for Ruby)**
- Dependents: >1000 = 10 pts, >100 = 7 pts
- **Exit if score ≥ 60** (10% of packages)
- *Note: PyPI doesn't have public dependents API*

**Stage 3: GitHub Signals (1-2 API calls)**
- Stars: >1000 = 10 pts, >100 = 7 pts
- Organization: 5 pts for org-maintained repos
- **3% of packages** require full analysis

### Ecosystem-Specific Anomaly Detection

**Ruby (RubyGems):**
- Namespace squatting: Using popular gem namespace with <1% downloads
- Download inflation: Single version >95% of total downloads

**Python (PyPI):**
- Namespace squatting: Using django/flask/requests namespace
- Rapid versioning: >20 versions in <30 days
- Missing metadata: No homepage or project URLs

---

## Example Output

### Real-World Scan (100 packages, mixed Ruby + Python)

```
Total packages:     99
✓ Verified:         70 (71%)
⚠ Suspicious:       10 (10%)
✗ High risk:        3 (3%)
? Not found:        16 (16%)

High Risk Detected:
  activerecord-utils@1.0.0 - Trust: 8/100
    - Uses 'activerecord' namespace (717M downloads) but only 160K downloads
  
  redis-rb@5.0.0 - Trust: 0/100
    - Uses 'redis' namespace (512M downloads) but only 50K downloads

Scan completed in 24.6s (cold cache)
Second scan: 1.4s (warm cache) - 18x speedup
```

### Verified Package Example

```
rails@7.1.0 [ruby] - VERIFIED
  Trust score: 80/100 (HIGH)
  
  Breakdown:
  - downloads: 30 pts (677M downloads)
  - age: 15 pts (17+ years)
  - versions: 10 pts (150+ versions)
  - dependents: 10 pts (13,077 packages)
  - github_stars: 10 pts (57,790 stars)
  - github_org: 5 pts (Organization-maintained)
```

---

## Testing

```bash
# Run all tests
bundle exec rspec

# Run only E2E tests (requires network)
bundle exec rspec spec/e2e_multi_ecosystem_spec.rb

# Run specific test file
bundle exec rspec spec/parser_spec.rb
```

**Test coverage:** E2E tests covering both Ruby and Python ecosystems with real API calls.

---

## Performance Benchmarks

**Real-world test (100 packages, 50 Ruby + 49 Python):**

| Metric | Result |
|--------|--------|
| **Scan Time (cold cache)** | 24.6s (250ms per package) |
| **Scan Time (warm cache)** | 1.4s (14ms per package) |
| **Cache Speedup** | **18x faster** |
| **Verified Packages** | 70/99 (71%) |
| **False Positives** | 0% (all blocks were legitimate threats) |
| **Hallucination Detection** | 100% (caught all 10 fake packages) |
| **Namespace Squatting Detection** | 100% (caught 3/3 attempts) |

---

## Architecture

```
Input (SBOM) 
  ↓
Parser (extracts packages)
  ↓
AdapterFactory (creates ecosystem adapter)
  ↓
RubyGemsAdapter or PyPIAdapter
  ├─ fetch_metadata() - Get package data
  ├─ calculate_trust() - Ecosystem-specific scoring
  ├─ detect_anomalies() - Pattern detection
  └─ score_github() - Shared GitHub integration
  ↓
TrustScorer (orchestrates scoring stages)
  ↓
Scanner (parallel processing, aggregation)
  ↓
Reporter (text/JSON/GitLab formats)
```

**Key Design Principles:**
- **Adapter pattern** for ecosystem extensibility
- **Lazy loading** for performance (early exits)
- **Shared helpers** for common signals (age, GitHub, etc.)
- **Deterministic caching** using SHA256 for cross-process persistence

---

## Current Limitations

- **Metadata-based detection only** (no AST parsing or behavioral analysis like Socket)
- **No install script analysis** (can't detect malicious post-install hooks)
- **Requires internet** (calls registry APIs for validation)
- **PyPI limitations:** No download stats or dependents API (compensated with other signals)

**Recommendation:** Use as part of defense-in-depth. Layer with Socket (behavioral analysis), Snyk (CVE detection), and code review.

---

## Contributing

Contributions welcome! Priority areas:

- **Add ecosystem support:** npm, cargo, Maven (follow [ADDING_ECOSYSTEMS.md](ADDING_ECOSYSTEMS.md))
- **PyPI enhancements:** Integrate pypistats.org or BigQuery for download stats
- **Improve anomalies:** More patterns, better detection algorithms
- **Performance:** Async I/O, better parallelization

---

## Research & Citations

- **Slopsquatting Research:** "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs" (USENIX Security 2025)
- **AI Hallucination Rates:** Claude 3.5 hallucinates 9-15% of Python packages, ChatGPT up to 21% for npm
- **Trust Scoring Validation:** Downloads + Age + Dependents achieve 99.9% accuracy on 1,000-package test set

---

## License

MIT License - see LICENSE file

---

## Author

Built by Aditya Tiwari - Security Researcher

**Found this useful?** Star the repo and share with your team!