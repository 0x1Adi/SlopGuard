require_relative '../ecosystem_adapter'

module SlopGuard
  module Adapters
    class RubyGemsAdapter < EcosystemAdapter
      def fetch_metadata(package_name)
        cache_key = "meta:ruby:#{package_name}"
        cached = @cache.get(cache_key, ttl: Cache::METADATA_TTL)
        return cached if cached

        metadata = @http.get("https://rubygems.org/api/v1/gems/#{package_name}.json")
        return nil unless metadata

        versions = fetch_versions(package_name)
        
        result = { metadata: metadata, versions: versions }
        @cache.set(cache_key, result, ttl: Cache::METADATA_TTL)
        result
      end

      def calculate_trust(package_name, metadata, versions)
        score = 0
        breakdown = []

        # Downloads (max 30 points)
        downloads_result = score_downloads(
          metadata[:downloads].to_i,
          critical: 100_000_000,
          high: 10_000_000,
          medium: 1_000_000
        )
        score += downloads_result[:score]
        breakdown.concat(downloads_result[:breakdown])

        # Age and version history (max 25 points)
        age_result = score_age(versions, max_points: 15)
        score += age_result[:score]
        breakdown.concat(age_result[:breakdown])

        versions_result = score_versions(versions, max_points: 10)
        score += versions_result[:score]
        breakdown.concat(versions_result[:breakdown])

        { score: score, breakdown: breakdown }
      end

      def fetch_dependents_count(package_name)
        cache_key = "deps:ruby:#{package_name}"
        deps = @cache.get(cache_key, ttl: Cache::TRUST_TTL)
        
        unless deps
          data = @http.get("https://rubygems.org/api/v1/gems/#{package_name}/reverse_dependencies.json")
          deps = data || []
          @cache.set(cache_key, deps, ttl: Cache::TRUST_TTL)
        end

        deps.size
      end

      def extract_github_url(metadata)
        url = metadata.dig(:metadata, :source_code_uri) || 
              metadata[:source_code_uri] ||
              metadata.dig(:metadata, :homepage_uri) ||
              metadata[:homepage_uri]
        
        return nil unless url&.include?('github.com')

        match = url.match(%r{github\.com/([^/]+)/([^/\.]+)})
        return nil unless match

        { org: match[1], repo: match[2] }
      end

      def detect_anomalies(package_name, metadata, versions)
        anomalies = []

        # Check for namespace squatting
        if package_name.include?('-') || package_name.include?('_')
          base = package_name.split(/[-_]/).first
          base_downloads = fetch_base_package_downloads(base)
          
          if base_downloads && base_downloads > 10_000_000
            pkg_downloads = metadata[:downloads].to_i
            if pkg_downloads < base_downloads * 0.01
              anomalies << {
                type: 'namespace_squat',
                severity: 'HIGH',
                description: "Uses '#{base}' namespace (#{format_count(base_downloads)} downloads) but only #{format_count(pkg_downloads)} downloads"
              }
            end
          end
        end

        # Check for download inflation
        recent_version = versions.max_by { |v| Time.parse(v[:created_at]) rescue Time.at(0) }
        if recent_version
          version_downloads = recent_version[:downloads_count].to_i
          total_downloads = metadata[:downloads].to_i
          
          if version_downloads > 0 && total_downloads > 0
            ratio = version_downloads.to_f / total_downloads
            if ratio > 0.95 && total_downloads > 100_000
              anomalies << {
                type: 'download_inflation',
                severity: 'MEDIUM',
                description: "Single version accounts for #{(ratio * 100).round}% of downloads (suspicious)"
              }
            end
          end
        end

        anomalies
      end

      private

      def fetch_versions(package_name)
        cache_key = "versions:ruby:#{package_name}"
        versions = @cache.get(cache_key, ttl: Cache::TRUST_TTL)
        
        unless versions
          data = @http.get("https://rubygems.org/api/v1/versions/#{package_name}.json")
          versions = data || []
          @cache.set(cache_key, versions, ttl: Cache::TRUST_TTL)
        end

        versions
      end

      def fetch_base_package_downloads(base_name)
        base_meta = @http.get("https://rubygems.org/api/v1/gems/#{base_name}.json")
        base_meta ? base_meta[:downloads].to_i : nil
      end

      def format_count(count)
        if count >= 1_000_000
          "#{(count / 1_000_000.0).round(1)}M"
        elsif count >= 1_000
          "#{(count / 1_000.0).round(1)}K"
        else
          count.to_s
        end
      end
    end
  end
end
