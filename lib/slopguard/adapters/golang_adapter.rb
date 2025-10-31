require_relative '../ecosystem_adapter'
require 'uri'
require 'cgi'
require 'net/http'

module SlopGuard
  module Adapters
    class GolangAdapter < EcosystemAdapter
      PROXY_BASE = 'https://proxy.golang.org'
      DEPS_DEV_BASE = 'https://api.deps.dev/v3alpha'
      STDLIB_PREFIXES = ['golang.org/x/', 'std/', 'cmd/'].freeze
      
      def fetch_metadata(package_name)
        cache_key = "meta:go:#{package_name}"
        cached = @cache.get(cache_key, ttl: Cache::METADATA_TTL)
        return cached if cached

        # Check if standard library (skip APIs)
        if is_standard_library?(package_name)
          result = {
            metadata: { is_stdlib: true },
            versions: []
          }
          @cache.set(cache_key, result, ttl: Cache::METADATA_TTL)
          return result
        end

        encoded_name = CGI.escape(package_name)
        depsdev_data = fetch_depsdev_metadata(encoded_name)
        versions = fetch_versions_from_proxy(package_name)
        
        return nil if !depsdev_data && versions.empty?
        
        # Resolve GitHub URL for custom domains (stored as STRING)
        github_url = resolve_github_url(package_name)
        
        result = {
          metadata: (depsdev_data || {}).merge(
            is_stdlib: false,
            github_url: github_url  # STRING: "github.com/org/repo"
          ),
          versions: versions
        }
        
        @cache.set(cache_key, result, ttl: Cache::METADATA_TTL)
        result
      end

      def calculate_trust(package_name, metadata, versions)
        # Check stdlib flag FIRST
        if metadata[:is_stdlib]
          return {
            score: 95,
            breakdown: [{ signal: 'standard_library', points: 95, reason: 'Official Go standard library' }]
          }
        end

        score = 0
        breakdown = []

        # GitHub stars (20 points)
        stars_result = score_github_stars(metadata)
        score += stars_result[:score]
        breakdown.concat(stars_result[:breakdown])

        # OpenSSF Scorecard (20 points)
        scorecard_result = score_scorecard(metadata)
        score += scorecard_result[:score]
        breakdown.concat(scorecard_result[:breakdown])

        # Age (10 points)
        age_result = score_age(versions, max_points: 10)
        score += age_result[:score]
        breakdown.concat(age_result[:breakdown])

        # Versions (5 points)
        versions_result = score_versions(versions, max_points: 5)
        score += versions_result[:score]
        breakdown.concat(versions_result[:breakdown])

        # Vulnerabilities (deduction)
        vuln_result = check_vulnerabilities(metadata)
        score += vuln_result[:score]
        breakdown.concat(vuln_result[:breakdown])

        # License (5 points)
        license_result = score_license(metadata)
        score += license_result[:score]
        breakdown.concat(license_result[:breakdown])

        # Dependencies (5 points)
        deps_result = score_dependency_count(metadata)
        score += deps_result[:score]
        breakdown.concat(deps_result[:breakdown])

        # Repository quality (5 points)
        repo_result = score_repository_quality(metadata)
        score += repo_result[:score]
        breakdown.concat(repo_result[:breakdown])

        { score: score, breakdown: breakdown }
      end

      def extract_github_url(metadata)
        github_url = metadata[:github_url]
        return nil unless github_url
        
        # Parse STRING "github.com/org/repo" into HASH
        if github_url.start_with?('github.com/')
          parts = github_url.sub('github.com/', '').split('/')
          return { org: parts[0], repo: parts[1] } if parts.size >= 2
        end
        
        nil
      end

      def detect_anomalies(package_name, metadata, versions)
        anomalies = []

        typosquat = check_typosquatting(package_name)
        anomalies << typosquat if typosquat

        churn = check_version_churn(versions)
        anomalies << churn if churn

        age_anomaly = check_repository_age(package_name, versions)
        anomalies << age_anomaly if age_anomaly

        anomalies
      end

      private

      # Returns STRING: "github.com/org/repo" or nil
      def resolve_github_url(package_name)
        # Already github.com? Return as STRING
        if package_name.start_with?('github.com/')
          parts = package_name.sub('github.com/', '').split('/')
          return "github.com/#{parts[0]}/#{parts[1]}" if parts.size >= 2
        end
        
        # Special case: google.golang.org packages are mirrored on GitHub
        if package_name.start_with?('google.golang.org/')
          pkg = package_name.sub('google.golang.org/', '')
          return "github.com/protocolbuffers/protobuf-go" if pkg.start_with?('protobuf')
          return "github.com/grpc/grpc-go" if pkg.start_with?('grpc')
        end
        
        # For custom domains, fetch go-get meta tag
        cache_key = "github_url:#{package_name}"
        cached = @cache.get(cache_key, ttl: 604800)
        return cached if cached
        
        # Fetch HTML and parse go-import meta tag
        begin
          uri = URI("https://#{package_name}?go-get=1")
          response = Net::HTTP.get_response(uri)
          
          if response.code == '200'
            html = response.body
            # Parse: <meta name="go-import" content="gorm.io/gorm git https://github.com/go-gorm/gorm">
            match = html.match(/<meta\s+name="go-import"\s+content="[^"]*\s+git\s+https:\/\/github\.com\/([^"\/]+)\/([^"\/\s]+)/)
            if match
              github_url = "github.com/#{match[1]}/#{match[2]}"
              @cache.set(cache_key, github_url, ttl: 604800)
              return github_url
            end
          end
        rescue => e
          # Ignore errors
        end
        
        @cache.set(cache_key, nil, ttl: 604800)
        nil
      end

      def fetch_depsdev_metadata(encoded_name)
        url = "#{DEPS_DEV_BASE}/systems/go/packages/#{encoded_name}"
        @http.get(url)
      rescue
        nil
      end

      def fetch_versions_from_proxy(package_name)
        cache_key = "versions:go:#{package_name}"
        cached = @cache.get(cache_key, ttl: 604800)
        return cached if cached

        uri = URI("#{PROXY_BASE}/#{package_name}/@v/list")
        response = make_plain_text_request(uri)
        return [] unless response

        version_list = response.split("\n").map(&:strip).reject(&:empty?)
        
        # Get timestamps for recent versions only
        versions = version_list.last(20).map do |version|
          info_url = "#{PROXY_BASE}/#{package_name}/@v/#{version}.info"
          info = @http.get(info_url)
          
          {
            number: version,
            created_at: info ? info[:Time] : nil
          }
        end.compact

        @cache.set(cache_key, versions, ttl: 604800)
        versions
      rescue
        []
      end

      def make_plain_text_request(uri)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.read_timeout = 10
        http.open_timeout = 5
        
        request = Net::HTTP::Get.new(uri)
        request['User-Agent'] = 'SlopGuard/1.0'
        
        response = http.request(request)
        response.is_a?(Net::HTTPSuccess) ? response.body : nil
      rescue
        nil
      end

      def is_standard_library?(package_name)
        STDLIB_PREFIXES.any? { |prefix| package_name.start_with?(prefix) }
      end

      # Uses STRING github_url from metadata
      def score_github_stars(metadata)
        github_url = metadata[:github_url]  # STRING or nil
        return { score: 0, breakdown: [] } unless github_url
        
        # Call projects API with STRING URL
        encoded = CGI.escape(github_url)
        project_url = "#{DEPS_DEV_BASE}/projects/#{encoded}"
        project_data = @http.get(project_url)
        
        return { score: 0, breakdown: [] } unless project_data
        
        stars = project_data[:starsCount] || 0

        points = case stars
                 when 0...100 then 0
                 when 100...500 then 5
                 when 500...2000 then 10
                 when 2000...10000 then 15
                 else 20
                 end

        {
          score: points,
          breakdown: [{ 
            signal: 'github_stars', 
            points: points, 
            reason: "#{stars} GitHub stars" 
          }]
        }
      end

      # Uses STRING github_url from metadata
      def score_scorecard(metadata)
        github_url = metadata[:github_url]  # STRING or nil
        return { score: 10, breakdown: [{ signal: 'scorecard', points: 10, reason: 'Scorecard not available' }] } unless github_url
        
        # Call projects API with STRING URL
        encoded = CGI.escape(github_url)
        project_url = "#{DEPS_DEV_BASE}/projects/#{encoded}"
        project_data = @http.get(project_url)
        
        scorecard = project_data&.dig(:scorecard)
        return { score: 10, breakdown: [{ signal: 'scorecard', points: 10, reason: 'Scorecard not available' }] } unless scorecard

        overall_score = scorecard[:overallScore] || 0
        
        points = case overall_score
                 when 8..10 then 20
                 when 6...8 then 15
                 when 4...6 then 10
                 when 2...4 then 5
                 else 0
                 end

        {
          score: points,
          breakdown: [{ 
            signal: 'openssf_scorecard', 
            points: points, 
            reason: "OpenSSF Scorecard: #{overall_score}/10" 
          }]
        }
      end

      def check_vulnerabilities(metadata)
        advisories = []
        
        if metadata[:versions]
          latest_version = metadata[:versions].last
          advisories = latest_version[:advisoryKeys] || [] if latest_version
        end

        return { score: 0, breakdown: [] } if advisories.empty?

        penalty = advisories.size * -10
        penalty = [penalty, -30].max

        {
          score: penalty,
          breakdown: [{ 
            signal: 'vulnerabilities', 
            points: penalty, 
            reason: "#{advisories.size} known vulnerabilities" 
          }]
        }
      end

      def score_license(metadata)
        licenses = []
        
        if metadata[:versions]
          latest_version = metadata[:versions].last
          licenses = latest_version[:licenses] || [] if latest_version
        end

        return { score: 0, breakdown: [{ signal: 'license', points: 0, reason: 'No license' }] } if licenses.empty?

        recognized = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'GPL', 'LGPL']
        has_recognized = licenses.any? { |l| recognized.any? { |r| l.to_s.include?(r) } }

        points = has_recognized ? 5 : 0

        {
          score: points,
          breakdown: [{ 
            signal: 'license', 
            points: points, 
            reason: "License: #{licenses.join(', ')}" 
          }]
        }
      end

      def score_dependency_count(metadata)
        dep_count = 0
        
        if metadata[:versions]
          latest_version = metadata[:versions].last
          if latest_version && latest_version[:versionKey]
            pkg_name = latest_version[:versionKey][:name]
            version = latest_version[:versionKey][:version]
            
            encoded_name = CGI.escape(pkg_name)
            encoded_version = CGI.escape(version)
            deps_url = "#{DEPS_DEV_BASE}/systems/go/packages/#{encoded_name}/versions/#{encoded_version}:dependencies"
            
            deps_data = @http.get(deps_url)
            dep_count = deps_data[:nodes]&.size || 0 if deps_data
          end
        end

        points = case dep_count
                 when 0...5 then 5
                 when 5...20 then 3
                 when 20...50 then 1
                 else 0
                 end

        {
          score: points,
          breakdown: [{ 
            signal: 'dependencies', 
            points: points, 
            reason: "#{dep_count} dependencies" 
          }]
        }
      end

      def score_repository_quality(metadata)
        github_url = metadata[:github_url]
        quality_score = github_url ? 5 : 0

        {
          score: quality_score,
          breakdown: [{ 
            signal: 'repository_quality', 
            points: quality_score, 
            reason: github_url ? 'Source repository identified' : 'No source repository' 
          }]
        }
      end

      def check_typosquatting(package_name)
        suspicious_patterns = [
          /-go$/, 
          /^golang-/, 
          /ii+/, 
          /\d{2,}$/
        ]

        suspicious_patterns.each do |pattern|
          if package_name.match?(pattern)
            return {
              type: 'typosquat',
              severity: 'MEDIUM',
              description: "Suspicious naming pattern: #{pattern.inspect}"
            }
          end
        end

        nil
      end

      def check_version_churn(versions)
        return nil if versions.size < 5

        recent = versions.select do |v|
          v[:created_at] && Time.parse(v[:created_at]) > (Time.now - 7 * 86400)
        end

        if recent.size > 5
          {
            type: 'rapid_versioning',
            severity: 'MEDIUM',
            description: "#{recent.size} versions in 7 days"
          }
        end
      end

      def check_repository_age(package_name, versions)
        return nil if versions.empty?

        valid_versions = versions.select { |v| v[:created_at] }
        return nil if valid_versions.empty?

        oldest = valid_versions.min_by { |v| Time.parse(v[:created_at]) }
        age_days = (Time.now - Time.parse(oldest[:created_at])) / 86400

        if age_days < 90
          {
            type: 'new_package',
            severity: 'LOW',
            description: "Package is only #{age_days.to_i} days old"
          }
        end
      end
    end
  end
end