module SlopGuard
  class TrustScorer
    def initialize(http, cache)
      @http = http
      @cache = cache
    end

    def score(package, metadata)
      score = 0
      breakdown = []

      basic = score_basic(metadata, package[:name])
      score += basic[:score]
      breakdown.concat(basic[:breakdown])
      return finalize(score, breakdown, 1) if score >= 80

      deps = score_dependencies(package[:name])
      score += deps[:score]
      breakdown.concat(deps[:breakdown])
      return finalize(score, breakdown, 2) if score >= 70

      gh = score_github(metadata)
      score += gh[:score]
      breakdown.concat(gh[:breakdown])

      finalize(score, breakdown, 3)
    end

    private

    def score_basic(meta, package_name)
      score = 0
      breakdown = []
      
      downloads = meta[:downloads].to_i
      if downloads > 10_000_000
        score += 30
        breakdown << { signal: 'downloads', points: 30, reason: 'Critical infrastructure' }
      elsif downloads > 1_000_000
        score += 25
        breakdown << { signal: 'downloads', points: 25, reason: 'Widely adopted' }
      elsif downloads > 100_000
        score += 20
        breakdown << { signal: 'downloads', points: 20, reason: 'Well adopted' }
      elsif downloads > 10_000
        score += 10
        breakdown << { signal: 'downloads', points: 10, reason: 'Moderate adoption' }
      end

      age_score = score_age(package_name)
      score += age_score[:score]
      breakdown.concat(age_score[:breakdown])

      { score: score, breakdown: breakdown }
    end

    def score_age(package_name)
      cache_key = "versions:#{package_name}"
      versions = @cache.get(cache_key, ttl: Cache::TRUST_TTL)
      
      unless versions
        data = @http.get("https://rubygems.org/api/v1/versions/#{package_name}.json")
        return { score: 0, breakdown: [] } unless data
        versions = data
        @cache.set(cache_key, versions, ttl: Cache::TRUST_TTL)
      end

      return { score: 0, breakdown: [] } if versions.empty?

      # Filter out versions without created_at
      valid_versions = versions.select { |v| v[:created_at] }
      return { score: 0, breakdown: [] } if valid_versions.empty?

      oldest = valid_versions.min_by { |v| Time.parse(v[:created_at]) }
      age_days = (Time.now - Time.parse(oldest[:created_at])) / 86400

      score = 0
      breakdown = []
      
      if age_days > 730
        score = 15
        breakdown << { signal: 'age', points: 15, reason: 'Mature (2+ years)' }
      elsif age_days > 365
        score = 10
        breakdown << { signal: 'age', points: 10, reason: 'Established (1+ year)' }
      elsif age_days > 180
        score = 5
        breakdown << { signal: 'age', points: 5, reason: 'Survived initial period' }
      end

      version_count = versions.size
      if version_count > 20
        score += 10
        breakdown << { signal: 'versions', points: 10, reason: 'Active development' }
      elsif version_count > 10
        score += 7
        breakdown << { signal: 'versions', points: 7, reason: 'Regular releases' }
      elsif version_count > 5
        score += 4
        breakdown << { signal: 'versions', points: 4, reason: 'Multiple releases' }
      end

      { score: score, breakdown: breakdown }
    end

    def score_dependencies(name)
      cache_key = "deps:#{name}"
      deps = @cache.get(cache_key, ttl: Cache::TRUST_TTL)
      
      unless deps
        data = @http.get("https://rubygems.org/api/v1/gems/#{name}/reverse_dependencies.json")
        deps = data || []
        @cache.set(cache_key, deps, ttl: Cache::TRUST_TTL)
      end

      count = deps.size
      score = 0
      reason = ''

      if count > 1000
        score = 10
        reason = "Used by #{count} packages"
      elsif count > 100
        score = 7
        reason = "Used by #{count} packages"
      elsif count > 10
        score = 4
        reason = "Used by #{count} packages"
      end

      breakdown = score > 0 ? [{ signal: 'dependents', points: score, reason: reason }] : []
      { score: score, breakdown: breakdown }
    end

    def score_github(meta)
      url = meta.dig(:metadata, :source_code_uri) || meta[:source_code_uri]
      return { score: 0, breakdown: [] } unless url&.include?('github.com')

      match = url.match(%r{github\.com/([^/]+)/([^/\.]+)})
      return { score: 0, breakdown: [] } unless match

      org, repo = match[1], match[2]
      cache_key = "gh:#{org}/#{repo}"
      
      data = @cache.get(cache_key, ttl: Cache::TRUST_TTL)
      unless data
        data = @http.get("https://api.github.com/repos/#{org}/#{repo}")
        return { score: 0, breakdown: [] } unless data
        return { score: 0, breakdown: [] } if data[:message] # GitHub error response
        @cache.set(cache_key, data, ttl: Cache::TRUST_TTL)
      end

      return { score: 0, breakdown: [] } unless data

      score = 0
      breakdown = []

      stars = data[:stargazers_count].to_i
      if stars > 1000
        score += 10
        breakdown << { signal: 'github_stars', points: 10, reason: "#{stars} stars" }
      elsif stars > 100
        score += 7
        breakdown << { signal: 'github_stars', points: 7, reason: "#{stars} stars" }
      end

      if data.dig(:owner, :type) == 'Organization'
        score += 5
        breakdown << { signal: 'github_org', points: 5, reason: 'Organization-maintained' }
      end

      { score: score, breakdown: breakdown }
    end

    def finalize(score, breakdown, stage)
      score = [[score, 0].max, 100].min
      level = case score
              when 95..100 then 'CRITICAL'
              when 80..94 then 'HIGH'
              when 60..79 then 'MEDIUM'
              when 40..59 then 'LOW'
              else 'UNTRUSTED'
              end
      
      { score: score, level: level, breakdown: breakdown, stage: stage }
    end
  end
end
