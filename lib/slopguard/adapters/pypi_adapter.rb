require_relative '../ecosystem_adapter'

module SlopGuard
  module Adapters
    class PyPIAdapter < EcosystemAdapter
      def fetch_metadata(package_name)
        # Normalize: PyPI treats dashes and underscores as equivalent
        normalized = normalize_name(package_name)
        
        cache_key = "meta:pypi:#{normalized}"
        cached = @cache.get(cache_key, ttl: Cache::METADATA_TTL)
        return cached if cached

        data = @http.get("https://pypi.org/pypi/#{normalized}/json")
        return nil unless data

        # PyPI returns everything in one call
        result = {
          metadata: data[:info],
          versions: parse_versions(data[:releases], data[:info])
        }
        
        @cache.set(cache_key, result, ttl: Cache::METADATA_TTL)
        result
      end

      def calculate_trust(package_name, metadata, versions)
        score = 0
        breakdown = []

        # PyPI doesn't expose downloads or dependents easily
        # Compensate with higher weight on available signals
        
        # Age (25 points - increased from Ruby's 15)
        age_result = score_age(versions, max_points: 25)
        score += age_result[:score]
        breakdown.concat(age_result[:breakdown])

        # Version history (20 points - increased from Ruby's 10)
        versions_result = score_versions(versions, max_points: 20)
        score += versions_result[:score]
        breakdown.concat(versions_result[:breakdown])

        # Classifiers (15 points - PyPI-specific)
        classifiers = metadata[:classifiers] || []
        classifiers_result = score_classifiers(classifiers)
        score += classifiers_result[:score]
        breakdown.concat(classifiers_result[:breakdown])
        
        # License presence (5 points)
        if metadata[:license] && !metadata[:license].empty?
          score += 5
          breakdown << { signal: 'license', points: 5, reason: 'License declared' }
        end

        # Modern Python support (5 points)
        if metadata[:requires_python] && metadata[:requires_python].include?('3.')
          score += 5
          breakdown << { signal: 'python_support', points: 5, reason: 'Modern Python support' }
        end

        { score: score, breakdown: breakdown }
      end

      def fetch_dependents_count(package_name)
        # PyPI doesn't provide a public dependents API
        # Would need to integrate with libraries.io or similar
        nil
      end

      def extract_github_url(metadata)
        # Check project URLs first
        project_urls = metadata[:project_urls] || {}
        github_url = project_urls.values.find { |url| url&.include?('github.com') }
        
        # Fallback to home page
        github_url ||= metadata[:home_page] if metadata[:home_page]&.include?('github.com')
        
        return nil unless github_url

        match = github_url.match(%r{github\.com/([^/]+)/([^/\.]+)})
        return nil unless match

        { org: match[1], repo: match[2] }
      end

      def detect_anomalies(package_name, metadata, versions)
        anomalies = []

        # Check for namespace squatting (common with popular packages)
        normalized = normalize_name(package_name)
        if normalized.include?('-')
          base = normalized.split('-').first
          
          # Common Python base packages that are targets for squatting
          popular_bases = %w[django flask requests numpy pandas tensorflow pytorch]
          
          if popular_bases.include?(base)
            anomalies << {
              type: 'namespace_squat',
              severity: 'HIGH',
              description: "Uses popular '#{base}' namespace - verify this is legitimate"
            }
          end
        end

        # Check for suspiciously new packages with many versions
        if versions.size > 10
          newest_version = versions.max_by { |v| Time.parse(v[:created_at]) rescue Time.at(0) }
          oldest_version = versions.min_by { |v| Time.parse(v[:created_at]) rescue Time.now }
          
          if newest_version && oldest_version
            age_days = (Time.parse(newest_version[:created_at]) - Time.parse(oldest_version[:created_at])) / 86400
            
            if age_days < 30 && versions.size > 20
              anomalies << {
                type: 'rapid_versioning',
                severity: 'MEDIUM',
                description: "#{versions.size} versions released in #{age_days.round} days (suspicious)"
              }
            end
          end
        end

        # Check for missing important metadata
        if !metadata[:home_page] && !metadata[:project_urls]
          anomalies << {
            type: 'missing_metadata',
            severity: 'LOW',
            description: "No homepage or project URLs provided"
          }
        end

        anomalies
      end

      private

      def normalize_name(name)
        # PyPI normalization: lowercase, replace underscores with dashes
        name.downcase.gsub('_', '-')
      end

      def parse_versions(releases, info)
        versions = []
        
        releases.each do |version_number, files|
          next if files.empty?
          
          # Get upload time from first file (they're all uploaded together)
          first_file = files.first
          next unless first_file
          
          versions << {
            number: version_number,
            created_at: first_file[:upload_time] || first_file[:upload_time_iso_8601],
            yanked: first_file[:yanked] || false
          }
        end

        # Filter out yanked versions for trust calculation
        versions.reject { |v| v[:yanked] }
      end

      def score_classifiers(classifiers)
        score = 0
        breakdown = []

        # Development Status classifiers indicate maturity
        status = classifiers.find { |c| c.start_with?('Development Status ::') }
        
        if status
          case status
          when /7 - Inactive/
            # Inactive packages get no points
          when /6 - Mature/, /5 - Production/
            score += 10
            breakdown << { signal: 'maturity', points: 10, reason: 'Mature/Production status' }
          when /4 - Beta/
            score += 5
            breakdown << { signal: 'maturity', points: 5, reason: 'Beta status' }
          when /3 - Alpha/
            score += 2
            breakdown << { signal: 'maturity', points: 2, reason: 'Alpha status' }
          end
        end

        # License classifier indicates completeness
        has_license = classifiers.any? { |c| c.start_with?('License ::') && !c.include?('OSI Approved') }
        if has_license
          score += 5
          breakdown << { signal: 'license', points: 5, reason: 'License declared' }
        end

        { score: score, breakdown: breakdown }
      end
    end
  end
end
