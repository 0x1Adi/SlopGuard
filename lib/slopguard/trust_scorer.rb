module SlopGuard
  class TrustScorer
    def initialize(http, cache)
      @http = http
      @cache = cache
    end

    def score(package, metadata)
      score = 0
      breakdown = []
      timings = {}

      t1 = Time.now
      versions = fetch_versions(package[:name])
      timings[:fetch_versions] = ((Time.now - t1) * 1000).round(2)
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - fetch_versions: #{timings[:fetch_versions]}ms" if ENV['PROFILE']

      t2 = Time.now
      basic = score_basic(metadata, package[:name], versions)
      score += basic[:score]
      breakdown.concat(basic[:breakdown])
      timings[:score_basic] = ((Time.now - t2) * 1000).round(2)
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - score_basic: #{timings[:score_basic]}ms (score now: #{score})" if ENV['PROFILE']
      
      return finalize(score, breakdown, 1) if score >= 80

      t3 = Time.now
      deps = score_dependencies(package[:name])
      score += deps[:score]
      breakdown.concat(deps[:breakdown])
      timings[:score_dependencies] = ((Time.now - t3) * 1000).round(2)
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - score_dependencies: #{timings[:score_dependencies]}ms (score now: #{score})" if ENV['PROFILE']
      
      return finalize(score, breakdown, 2) if score >= 70

      t4 = Time.now
      maint = score_maintainer(package, metadata)
      score += maint[:score]
      breakdown.concat(maint[:breakdown])
      timings[:score_maintainer] = ((Time.now - t4) * 1000).round(2)
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - score_maintainer: #{timings[:score_maintainer]}ms" if ENV['PROFILE']

      t5 = Time.now
      gh = score_github(metadata)
      score += gh[:score]
      breakdown.concat(gh[:breakdown])
      timings[:score_github] = ((Time.now - t5) * 1000).round(2)
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - score_github: #{timings[:score_github]}ms" if ENV['PROFILE']

      finalize(score, breakdown, 3)
    end

    private

    def fetch_versions(package_name)
      cache_key = "versions:#{package_name}"
      versions = @cache.get(cache_key, ttl: Cache::TRUST_TTL)
      
      unless versions
        data = @http.get("https://rubygems.org/api/v1/versions/#{package_name}.json")
        versions = data || []
        @cache.set(cache_key, versions, ttl: Cache::TRUST_TTL)
      end
      
      versions
    end

    def score_basic(meta, package_name, versions)
      score = 0
      breakdown = []
      
      # Downloads scoring (max 30 points)
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
      elsif downloads > 1_000
        score += 5
        breakdown << { signal: 'downloads', points: 5, reason: 'Some users' }
      end

      # Age + version scoring (max 25 points)
      age_score = score_age(versions)
      score += age_score[:score]
      breakdown.concat(age_score[:breakdown])

      { score: score, breakdown: breakdown }
    end

    def score_age(versions)
      return { score: 0, breakdown: [] } if versions.empty?

      valid_versions = versions.select { |v| v[:created_at] }
      return { score: 0, breakdown: [] } if valid_versions.empty?

      oldest = valid_versions.min_by { |v| Time.parse(v[:created_at]) }
      age_days = (Time.now - Time.parse(oldest[:created_at])) / 86400

      score = 0
      breakdown = []
      
      # Age scoring (max 15 points)
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

      # Version history (max 10 points)
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

      # Direct dependents (max 10 points)
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

    def score_maintainer(package, meta)
      score = 0
      breakdown = []

      # Extract maintainer email
      authors = meta[:authors]
      return { score: 0, breakdown: [] } unless authors

      # Check email domain verification
      package_name = package[:name]
      if package_name.include?('-') || package_name.include?('_')
        org_prefix = package_name.split(/[-_]/).first
        
        # Check if email domain matches package namespace
        if authors.is_a?(String) && authors.include?('@')
          domain = authors.split('@').last.split('.').first
          
          if domain == org_prefix
            score += 25
            breakdown << { signal: 'email_verification', points: 25, reason: "Email domain matches package namespace" }
            return { score: score, breakdown: breakdown }
          elsif authors.downcase.include?(org_prefix)
            score -= 15
            breakdown << { signal: 'unverified_org', points: -15, reason: "Uses org name without verified domain" }
          end
        end
      end

      # Fetch maintainer's other packages (if no domain match)
      if authors.is_a?(String) && authors.include?('@')
        maintainer_packages = fetch_maintainer_packages(authors)
        
        if maintainer_packages && maintainer_packages.any?
          # Exclude current package
          other_packages = maintainer_packages.reject { |p| p[:name] == package[:name] }
          
          total_downloads = other_packages.sum { |p| p[:downloads].to_i }
          
          # Reputation scoring (max 15 points)
          if total_downloads > 1_000_000
            score += 15
            breakdown << { signal: 'maintainer_reputation', points: 15, reason: "Proven track record (#{total_downloads} downloads across #{other_packages.size} packages)" }
          elsif total_downloads > 100_000
            score += 10
            breakdown << { signal: 'maintainer_reputation', points: 10, reason: "Established maintainer" }
          elsif other_packages.size > 5
            score += 5
            breakdown << { signal: 'maintainer_reputation', points: 5, reason: "Experienced (#{other_packages.size} packages)" }
          end

          # Account age from oldest package
          if other_packages.any?
            oldest_created = other_packages.map { |p| Time.parse(p[:created_at]) rescue nil }.compact.min
            if oldest_created
              account_age_days = (Time.now - oldest_created) / 86400
              
              if account_age_days > 730
                score += 5
                breakdown << { signal: 'account_age', points: 5, reason: "Account 2+ years old" }
              elsif account_age_days > 365
                score += 3
                breakdown << { signal: 'account_age', points: 3, reason: "Account 1+ year old" }
              end
            end
          end
        end
      end

      { score: score, breakdown: breakdown }
    end

    def fetch_maintainer_packages(email)
      # RubyGems doesn't have /owners/{email}/gems endpoint
      # So we cache maintainer data when we see it
      cache_key = "maintainer:#{email}"
      @cache.get(cache_key, ttl: Cache::TRUST_TTL)
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
        return { score: 0, breakdown: [] } if data[:message]
        @cache.set(cache_key, data, ttl: Cache::TRUST_TTL)
      end

      return { score: 0, breakdown: [] } unless data

      score = 0
      breakdown = []

      # Stars scoring (max 10 points)
      stars = data[:stargazers_count].to_i
      if stars > 1000
        score += 10
        breakdown << { signal: 'github_stars', points: 10, reason: "#{stars} stars" }
      elsif stars > 100
        score += 7
        breakdown << { signal: 'github_stars', points: 7, reason: "#{stars} stars" }
      elsif stars > 10
        score += 4
        breakdown << { signal: 'github_stars', points: 4, reason: "#{stars} stars" }
      end

      # Organization verification (max 5 points)
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
