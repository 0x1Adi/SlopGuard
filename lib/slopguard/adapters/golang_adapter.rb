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
            metadata: { is_stdlib: true },  # INSIDE metadata!
            versions: []
          }
          @cache.set(cache_key, result, ttl: Cache::METADATA_TTL)
          return result
        end

        encoded_name = CGI.escape(package_name)
        depsdev_data = fetch_depsdev_metadata(encoded_name)
        versions = fetch_versions_from_proxy(package_name)
        
        return nil if !depsdev_data && versions.empty?
        
        result = {
          metadata: (depsdev_data || {}).merge(is_stdlib: false),  # INSIDE metadata!
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

        # Dependent counts (20 points)
        dependents_result = score_dependents(package_name, metadata)
        score += dependents_result[:score]
        breakdown.concat(dependents_result[:breakdown])

        # GitHub stars (15 points) - use starsCount from projectData
        stars_result = score_github_stars(metadata)
        score += stars_result[:score]
        breakdown.concat(stars_result[:breakdown])

        # Age (10 points)
        age_result = score_age(versions, max_points: 10)
        score += age_result[:score]
        breakdown.concat(age_result[:breakdown])

        # Versions (5 points)
        versions_result = score_versions(versions, max_points: 5)
        score += versions_result[:score]
        breakdown.concat(versions_result[:breakdown])

        # OpenSSF Scorecard (20 points)
        scorecard_result = score_scorecard(package_name, metadata)
        score += scorecard_result[:score]
        breakdown.concat(scorecard_result[:breakdown])

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
        repo_result = score_repository_quality(package_name, metadata)
        score += repo_result[:score]
        breakdown.concat(repo_result[:breakdown])

        { score: score, breakdown: breakdown }
      end

      def fetch_dependents_count(package_name)
        cache_key = "deps:go:#{package_name}"
        cached = @cache.get(cache_key, ttl: Cache::TRUST_TTL)
        return cached if cached

        encoded_name = CGI.escape(package_name)
        url = "#{DEPS_DEV_BASE}/systems/go/packages/#{encoded_name}"
        
        data = @http.get(url)
        if data && data[:versions]
          latest = data[:versions].last
          if latest && latest[:versionKey]
            version = latest[:versionKey][:version]
            deps_url = "#{url}/versions/#{CGI.escape(version)}:dependents"
            deps_data = @http.get(deps_url)
            
            if deps_data
              count = (deps_data[:directDependentCount] || 0) + (deps_data[:indirectDependentCount] || 0)
              @cache.set(cache_key, count, ttl: Cache::TRUST_TTL)
              return count
            end
          end
        end

        @cache.set(cache_key, 0, ttl: Cache::TRUST_TTL)
        0
      end

      def extract_github_url(metadata)
        # Parse from package name for github.com modules
        package_name = metadata[:packageKey]&.dig(:name)
        if package_name && package_name.start_with?('github.com/')
          parts = package_name.sub('github.com/', '').split('/')
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

      def fetch_depsdev_metadata(encoded_name)
        url = "#{DEPS_DEV_BASE}/systems/go/packages/#{encoded_name}"
        data = @http.get(url)
        return nil unless data
        
        # Enrich with project data (scorecard + stars)
        if data[:packageKey]
          project_url = "#{DEPS_DEV_BASE}/projects/#{encoded_name}"
          project_data = @http.get(project_url)
          data[:projectData] = project_data if project_data
        end
        
        data
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
        
        # Get timestamps for recent versions only (performance)
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

      def score_dependents(package_name, metadata)
        count = fetch_dependents_count(package_name)
        
        points = case count
                 when 0...1 then 0
                 when 1...10 then 5
                 when 10...100 then 10
                 when 100...1000 then 15
                 else 20
                 end

        {
          score: points,
          breakdown: [{ 
            signal: 'dependents', 
            points: points, 
            reason: "#{count} dependent packages" 
          }]
        }
      end

      def score_github_stars(metadata)
        stars = 0
        
        # Stars from deps.dev projectData
        if metadata[:projectData]
          stars = metadata[:projectData][:starsCount] || 0
        end

        points = case stars
                 when 0...10 then 0
                 when 10...100 then 3
                 when 100...500 then 7
                 when 500...2000 then 11
                 else 15
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

      def score_scorecard(package_name, metadata)
        scorecard = metadata[:projectData]&.dig(:scorecard)

        unless scorecard
          encoded = CGI.escape(package_name)
          project_url = "#{DEPS_DEV_BASE}/projects/#{encoded}"
          project_data = @http.get(project_url)
          scorecard = project_data[:scorecard] if project_data
        end

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
        
        # Try projectData first
        if metadata[:projectData] && metadata[:projectData][:license]
          licenses = [metadata[:projectData][:license]]
        elsif metadata[:versions]
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

      def score_repository_quality(package_name, metadata)
        quality_score = 0
        
        if metadata[:projectData]
          project = metadata[:projectData]
          
          quality_score += 1 if project[:description] && !project[:description].empty?
          quality_score += 1 if project[:homepage] && !project[:homepage].empty?
          quality_score += 1 if project[:license] && !project[:license].empty?
          quality_score += 1 if project[:openIssuesCount]
          quality_score += 1 if project[:forksCount] && project[:forksCount] > 0
        end

        quality_score = [quality_score, 5].min

        {
          score: quality_score,
          breakdown: [{ 
            signal: 'repository_quality', 
            points: quality_score, 
            reason: 'Repository quality indicators' 
          }]
        }
      end

      def check_typosquatting(package_name)
        return nil unless package_name.start_with?('github.com/')

        parts = package_name.sub('github.com/', '').split('/')
        return nil if parts.size < 2

        repo_name = parts[1]

        suspicious_patterns = [/-go$/, /golang/, /^go-/, /([a-z])\1{2,}/]

        suspicious_patterns.each do |pattern|
          if repo_name.match?(pattern)
            return {
              type: 'potential_typosquat',
              severity: 'HIGH',
              description: "Repository name matches typosquatting pattern"
            }
          end
        end

        nil
      end

      def check_version_churn(versions)
        return nil if versions.size < 5

        recent_versions = versions.select do |v|
          next false unless v[:created_at]
          begin
            created = Time.parse(v[:created_at])
            (Time.now - created) < 7 * 86400
          rescue
            false
          end
        end

        if recent_versions.size > 5
          return {
            type: 'rapid_version_churn',
            severity: 'MEDIUM',
            description: "#{recent_versions.size} versions in 7 days"
          }
        end

        nil
      end

      def check_repository_age(package_name, versions)
        return nil if versions.empty?

        oldest_version = versions.min_by { |v| v[:created_at] || Time.now.to_s }
        return nil unless oldest_version[:created_at]

        begin
          first_publish = Time.parse(oldest_version[:created_at])
          age_days = (Time.now - first_publish) / 86400

          if age_days < 90
            return {
              type: 'new_package',
              severity: 'MEDIUM',
              description: "Package is only #{age_days.round} days old"
            }
          end
        rescue
          nil
        end

        nil
      end
    end
  end
end
