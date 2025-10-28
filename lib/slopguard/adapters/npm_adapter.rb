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
