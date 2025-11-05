# frozen_string_literal: true

require_relative '../ecosystem_adapter'

module SlopGuard
  module Adapters
    class PyPIAdapter < EcosystemAdapter
      def fetch_metadata(package_name)
        normalized = normalize_name(package_name)

        cache_key = "meta:pypi:#{normalized}"
        cached = @cache.get(cache_key, ttl: Cache::METADATA_TTL)
        return cached if cached

        data = @http.get("https://pypi.org/pypi/#{normalized}/json")
        return nil unless data

        result = {
          metadata: data[:info],
          versions: parse_versions(data[:releases], data[:info]),
        }

        @cache.set(cache_key, result, ttl: Cache::METADATA_TTL)
        result
      end

      def calculate_trust(_package_name, metadata, versions)
        score = 0
        breakdown = []

        age_result = score_age(versions, max_points: 25)
        score += age_result[:score]
        breakdown.concat(age_result[:breakdown])

        versions_result = score_versions(versions, max_points: 20)
        score += versions_result[:score]
        breakdown.concat(versions_result[:breakdown])

        classifiers = metadata[:classifiers] || []
        classifiers_result = score_classifiers(classifiers)
        score += classifiers_result[:score]
        breakdown.concat(classifiers_result[:breakdown])

        if metadata[:license] && !metadata[:license].empty?
          score += 5
          breakdown << { signal: 'license', points: 5, reason: 'License declared' }
        end

        if metadata[:requires_python]&.include?('3.')
          score += 5
          breakdown << { signal: 'python_support', points: 5, reason: 'Modern Python support' }
        end

        { score: score, breakdown: breakdown }
      end

      def fetch_dependents_count(_package_name)
        nil
      end

      def extract_github_url(metadata)
        project_urls = metadata[:project_urls] || {}
        github_url = project_urls.values.find { |url| url&.include?('github.com') }

        github_url ||= metadata[:home_page] if metadata[:home_page]&.include?('github.com')

        return nil unless github_url

        match = github_url.match(%r{github\.com/([^/]+)/([^/.]+)})
        return nil unless match

        { org: match[1], repo: match[2] }
      end

      def detect_anomalies(package_name, metadata, versions)
        anomalies = []

        normalized = normalize_name(package_name)
        if normalized.include?('-')
          base = normalized.split('-').first

          popular_bases = ['django', 'flask', 'requests', 'numpy', 'pandas', 'tensorflow', 'pytorch']

          if popular_bases.include?(base)
            anomalies << {
              type:        'namespace_squat',
              severity:    'HIGH',
              description: "Uses popular '#{base}' namespace - verify this is legitimate",
            }
          end
        end

        if versions.size > 10
          newest_version = versions.max_by do |v|
            Time.parse(v[:created_at])
          rescue StandardError
            Time.at(0)
          end
          oldest_version = versions.min_by do |v|
            Time.parse(v[:created_at])
          rescue StandardError
            Time.now
          end

          if newest_version && oldest_version
            age_days = (Time.parse(newest_version[:created_at]) - Time.parse(oldest_version[:created_at])) / 86_400

            if age_days < 30 && versions.size > 20
              anomalies << {
                type:        'rapid_versioning',
                severity:    'MEDIUM',
                description: "#{versions.size} versions released in #{age_days.round} days (suspicious)",
              }
            end
          end
        end

        if !metadata[:home_page] && !metadata[:project_urls]
          anomalies << {
            type:        'missing_metadata',
            severity:    'LOW',
            description: 'No homepage or project URLs provided',
          }
        end

        anomalies
      end

      private

      def normalize_name(name)
        name.downcase.gsub('_', '-')
      end

      def parse_versions(releases, _info)
        versions = []

        releases.each do |version_number, files|
          next if files.empty?

          first_file = files.first
          next unless first_file

          versions << {
            number:     version_number,
            created_at: first_file[:upload_time] || first_file[:upload_time_iso_8601],
            yanked:     first_file[:yanked] || false,
          }
        end

        versions.reject { |v| v[:yanked] }
      end

      def score_classifiers(classifiers)
        score = 0
        breakdown = []

        status = classifiers.find { |c| c.start_with?('Development Status ::') }

        if status
          case status
          when /7 - Inactive/
            # Inactive packages get no points - intentionally empty
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
