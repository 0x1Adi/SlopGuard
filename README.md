# SlopGuard

Detects AI-hallucinated package dependencies and supply chain attacks.

## Install
```bash
gem install bundler
bundle install
chmod +x slopguard
```

## Usage
```bash
./slopguard sbom.json              # Text output
./slopguard sbom.json --format json # JSON output
```

## How It Works

1. Parses CycloneDX SBOM
2. Checks package existence
3. Calculates trust scores (0-100)
4. Detects anomalies
5. Reports risks

Trust scoring uses downloads, age, dependents, maintainer reputation, and GitHub metrics.

## Testing
```bash
bundle exec rspec
```

Exit codes: 0 = pass, 1 = high-risk found, 2 = error
