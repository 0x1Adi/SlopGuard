# Adding New Ecosystem Support

SlopGuard uses an adapter pattern to support multiple package ecosystems. Adding support for a new ecosystem (npm, cargo, Maven, etc.) requires implementing a single adapter class.

## Quick Start

**Adding npm support takes ~200 lines of code:**

1. Create `lib/slopguard/adapters/npm_adapter.rb`
2. Update `lib/slopguard/adapter_factory.rb` to register the new adapter
3. Update `lib/slopguard/parser.rb` to recognize `pkg:npm/` PURLs
4. Write E2E tests

## Step 1: Create the Adapter

Create `lib/slopguard/adapters/npm_adapter.rb`:

```ruby
require_relative '../ecosystem_adapter'

module SlopGuard
  module Adapters
    class NpmAdapter < EcosystemAdapter
      def fetch_metadata(package_name)
        # Fetch from npm registry
        cache_key = "meta:npm:#{package_name}"
        cached = @cache.get(cache_key, ttl: Cache::METADATA_TTL)
        return cached if cached

        data = @http.get("https://registry.npmjs.org/#{package_name}")
        return nil unless data

        result = {
          metadata: extract_metadata(data),
          versions: parse_versions(data[:versions])
        }
        
        @cache.set(cache_key, result, ttl: Cache::METADATA_TTL)
        result
      end

      def calculate_trust(package_name, metadata, versions)
        score = 0
        breakdown = []

        # npm-specific signals
        downloads = fetch_weekly_downloads(package_name)
        if downloads
          # npm has weekly download stats
          annual_downloads = downloads * 52
          downloads_result = score_downloads(annual_downloads, 
            critical: 50_000_000,
            high: 5_000_000, 
            medium: 500_000
          )
          score += downloads_result[:score]
          breakdown.concat(downloads_result[:breakdown])
        end

        # Age and versions (shared logic)
        age_result = score_age(versions, max_points: 15)
        score += age_result[:score]
        breakdown.concat(age_result[:breakdown])

        versions_result = score_versions(versions, max_points: 10)
        score += versions_result[:score]
        breakdown.concat(versions_result[:breakdown])

        { score: score, breakdown: breakdown }
      end

      def fetch_dependents_count(package_name)
        # npm has a dependents API
        data = @http.get("https://registry.npmjs.org/-/v1/search?text=#{package_name}&size=0")
        data ? data[:total] : nil
      end

      def extract_github_url(metadata)
        repo_url = metadata.dig(:repository, :url)
        return nil unless repo_url&.include?('github.com')

        match = repo_url.match(%r{github\.com[:/]([^/]+)/([^/\.]+)})
        return nil unless match

        { org: match[1], repo: match[2] }
      end

      def detect_anomalies(package_name, metadata, versions)
        anomalies = []
        
        # npm-specific anomaly detection
        # e.g., check for typosquatting against popular packages
        
        anomalies
      end

      private

      def extract_metadata(data)
        latest_version = data[:'dist-tags'][:latest]
        data[:versions][latest_version.to_sym] || {}
      end

      def parse_versions(versions_data)
        versions_data.map do |version, data|
          {
            number: version.to_s,
            created_at: data[:time] || Time.now.iso8601,
            deprecated: data[:deprecated] || false
          }
        end.reject { |v| v[:deprecated] }
      end

      def fetch_weekly_downloads(package_name)
        data = @http.get("https://api.npmjs.org/downloads/point/last-week/#{package_name}")
        data ? data[:downloads] : nil
      end
    end
  end
end
```

## Step 2: Register the Adapter

Update `lib/slopguard/adapter_factory.rb`:

```ruby
def self.create(ecosystem, http_client, cache)
  case ecosystem.to_s.downcase
  when 'ruby', 'rubygems'
    Adapters::RubyGemsAdapter.new(http_client, cache)
  when 'python', 'pypi'
    Adapters::PyPIAdapter.new(http_client, cache)
  when 'javascript', 'npm'  # ADD THIS
    Adapters::NpmAdapter.new(http_client, cache)
  else
    raise ArgumentError, "Unsupported ecosystem: #{ecosystem}"
  end
end

def self.supported_ecosystems
  ['ruby', 'python', 'npm']  # ADD npm HERE
end
```

## Step 3: Update Parser

Update `lib/slopguard/parser.rb`:

```ruby
def parse_purl(purl)
  case purl
  when %r{^pkg:gem/([^@]+)@(.+)$}
    { name: $1, version: $2, ecosystem: 'ruby' }
  when %r{^pkg:pypi/([^@]+)@(.+)$}
    { name: $1, version: $2, ecosystem: 'python' }
  when %r{^pkg:npm/([^@]+)@(.+)$}  # ADD THIS
    { name: $1, version: $2, ecosystem: 'npm' }
  else
    nil
  end
end
```

## Step 4: Write Tests

Add to `spec/e2e_multi_ecosystem_spec.rb`:

```ruby
describe 'npm Packages' do
  it 'verifies popular npm packages' do
    components = [
      { 'purl' => 'pkg:npm/express@4.18.0' },
      { 'purl' => 'pkg:npm/react@18.2.0' }
    ]
    
    sbom_path = create_sbom(components)
    results = SlopGuard.scan(sbom_path)
    
    expect(results[:total]).to eq(2)
    expect(results[:not_found]).to eq(0)
  end
end
```

## That's It!

The adapter pattern means:
- **No changes** to TrustScorer, Scanner, Cache, or HttpClient
- **No if/else chains** based on ecosystem
- **Shared logic** (age scoring, GitHub scoring) is inherited
- **Ecosystem-specific logic** stays isolated in the adapter

## Ecosystem-Specific Considerations

### npm
- Uses `registry.npmjs.org` API
- Weekly download stats from `api.npmjs.org/downloads`
- Has built-in deprecation tracking
- Scoped packages: `@org/package`

### Cargo (Rust)
- Uses `crates.io` API
- Limited download stats (only total, not broken down)
- Strong convention around GitHub-hosted projects
- Feature flags matter for security

### Maven (Java)
- Uses `search.maven.org` API  
- GroupId:ArtifactId naming
- Sonatype vs Central repository distinction matters
- POM files contain rich metadata

### Go modules
- No central registry - just GitHub/GitLab URLs
- `proxy.golang.org` for metadata
- Module path = repository path
- Version based on git tags

## Common Patterns

All adapters should:

1. **Normalize package names** according to ecosystem conventions
2. **Handle caching** using the provided cache object with appropriate TTLs
3. **Detect ecosystem-specific anomalies** (e.g., npm typosquatting, PyPI namespace squatting)
4. **Extract reliable trust signals** (downloads, age, dependents, GitHub)
5. **Return nil gracefully** when packages don't exist
6. **Use shared helper methods** from EcosystemAdapter base class

## Testing Your Adapter

```bash
# Run only your ecosystem's E2E tests
bundle exec rspec spec/e2e_multi_ecosystem_spec.rb -e "npm"

# Run full test suite
bundle exec rspec
```

## Performance Targets

Each adapter should:
- Complete metadata fetch in <500ms per package
- Utilize caching to achieve 90%+ cache hit rate
- Support parallel processing (no shared mutable state)
- Handle API rate limits gracefully

## Need Help?

Check existing adapters:
- `lib/slopguard/adapters/rubygems_adapter.rb` - Full-featured reference
- `lib/slopguard/adapters/pypi_adapter.rb` - Handles name normalization
- `lib/slopguard/ecosystem_adapter.rb` - Base class with shared helpers
