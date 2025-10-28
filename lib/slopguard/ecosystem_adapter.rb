module SlopGuard
  # Base adapter defining the interface for ecosystem-specific operations
  class EcosystemAdapter
    def initialize(http_client, cache)
      @http = http_client
      @cache = cache
    end

    # Must implement: Fetch package metadata
    # Returns: { metadata: {...}, versions: [...] } or nil if package doesn't exist
    def fetch_metadata(package_name)
      raise NotImplementedError
    end

    # Must implement: Calculate ecosystem-specific trust signals
    # Returns: { score: int, breakdown: [...] }
    def calculate_trust(package_name, metadata, versions)
      raise NotImplementedError
    end

    # Optional: Fetch dependent packages count
    # Returns: integer or nil
    def fetch_dependents_count(package_name)
      nil
    end

    # Optional: Extract GitHub repository URL
    # Returns: { org: string, repo: string } or nil
    def extract_github_url(metadata)
      nil
    end

    # Optional: Ecosystem-specific anomaly detection
    # Returns: array of anomaly hashes
    def detect_anomalies(package_name, metadata, versions)
      []
    end

    # Shared helper methods (public so they can be called by TrustScorer or adapters)

    # Shared helper: Score package age
    def score_age(versions, max_points: 15)
      valid_versions = versions.select { |v| v[:created_at] }
      return { score: 0, breakdown: [] } if valid_versions.empty?

      oldest = valid_versions.min_by { |v| Time.parse(v[:created_at]) }
      age_days = (Time.now - Time.parse(oldest[:created_at])) / 86400

      score = 0
      breakdown = []
      
      if age_days > 730
        score = max_points
        breakdown << { signal: 'age', points: max_points, reason: 'Mature (2+ years)' }
      elsif age_days > 365
        score = (max_points * 0.67).round
        breakdown << { signal: 'age', points: score, reason: 'Established (1+ year)' }
      elsif age_days > 180
        score = (max_points * 0.33).round
        breakdown << { signal: 'age', points: score, reason: 'Survived initial period' }
      end

      { score: score, breakdown: breakdown }
    end

    # Shared helper: Score version history
    def score_versions(versions, max_points: 10)
      count = versions.size
      score = 0
      breakdown = []

      if count > 20
        score = max_points
        breakdown << { signal: 'versions', points: max_points, reason: 'Active development' }
      elsif count > 10
        score = (max_points * 0.7).round
        breakdown << { signal: 'versions', points: score, reason: 'Regular releases' }
      elsif count > 5
        score = (max_points * 0.4).round
        breakdown << { signal: 'versions', points: score, reason: 'Multiple releases' }
      end

      { score: score, breakdown: breakdown }
    end

    # Shared helper: Score downloads with configurable thresholds
    def score_downloads(download_count, critical: 100_000_000, high: 10_000_000, medium: 1_000_000, max_points: 30)
      score = 0
      breakdown = []

      if download_count > critical
        score = max_points
        breakdown << { signal: 'downloads', points: max_points, reason: "Critical infrastructure (#{format_count(download_count)} downloads)" }
      elsif download_count > high
        score = (max_points * 0.8).round
        breakdown << { signal: 'downloads', points: score, reason: "Widely used (#{format_count(download_count)} downloads)" }
      elsif download_count > medium
        score = (max_points * 0.5).round
        breakdown << { signal: 'downloads', points: score, reason: "Popular (#{format_count(download_count)} downloads)" }
      elsif download_count > 100_000
        score = (max_points * 0.3).round
        breakdown << { signal: 'downloads', points: score, reason: "Moderate usage (#{format_count(download_count)} downloads)" }
      end

      { score: score, breakdown: breakdown }
    end

    # Shared helper: Score GitHub stars
    def score_github(metadata, max_stars_points: 10, max_org_points: 5)
      github_info = extract_github_url(metadata)
      return { score: 0, breakdown: [] } unless github_info

      cache_key = "gh:#{github_info[:org]}/#{github_info[:repo]}"
      data = @cache.get(cache_key, ttl: Cache::TRUST_TTL)
      
      unless data
        headers = {}
        headers['Authorization'] = "token #{ENV['GITHUB_TOKEN']}" if ENV['GITHUB_TOKEN']
        
        data = @http.get("https://api.github.com/repos/#{github_info[:org]}/#{github_info[:repo]}", headers)
        return { score: 0, breakdown: [] } unless data
        return { score: 0, breakdown: [] } if data[:message]
        @cache.set(cache_key, data, ttl: Cache::TRUST_TTL)
      end

      score = 0
      breakdown = []

      stars = data[:stargazers_count].to_i
      if stars > 1000
        score += max_stars_points
        breakdown << { signal: 'github_stars', points: max_stars_points, reason: "#{stars} stars" }
      elsif stars > 100
        points = (max_stars_points * 0.7).round
        score += points
        breakdown << { signal: 'github_stars', points: points, reason: "#{stars} stars" }
      elsif stars > 10
        points = (max_stars_points * 0.4).round
        score += points
        breakdown << { signal: 'github_stars', points: points, reason: "#{stars} stars" }
      end

      if data.dig(:owner, :type) == 'Organization'
        score += max_org_points
        breakdown << { signal: 'github_org', points: max_org_points, reason: 'Organization-maintained' }
      end

      { score: score, breakdown: breakdown }
    end

    private

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
