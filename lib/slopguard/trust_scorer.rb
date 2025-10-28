module SlopGuard
  class TrustScorer
    def initialize(http, cache)
      @http = http
      @cache = cache
    end

    def score(package)
      ecosystem = package[:ecosystem]
      adapter = AdapterFactory.create(ecosystem, @http, @cache)
      
      # Fetch metadata using ecosystem adapter
      t1 = Time.now
      data = adapter.fetch_metadata(package[:name])
      timings = { fetch_metadata: ((Time.now - t1) * 1000).round(2) }
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - fetch_metadata: #{timings[:fetch_metadata]}ms" if ENV['PROFILE']
      
      return not_found_result(package[:name]) unless data
      
      metadata = data[:metadata]
      versions = data[:versions]
      
      score = 0
      breakdown = []

      # Stage 1: Basic trust (downloads + age + versions)
      t2 = Time.now
      basic = adapter.calculate_trust(package[:name], metadata, versions)
      score += basic[:score]
      breakdown.concat(basic[:breakdown])
      timings[:calculate_trust] = ((Time.now - t2) * 1000).round(2)
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - calculate_trust: #{timings[:calculate_trust]}ms (score: #{score})" if ENV['PROFILE']
      
      return finalize(score, breakdown, 1) if score >= 70  # Early exit if high trust from basic signals

      # Stage 2: Dependents (if available)
      t3 = Time.now
      deps_count = adapter.fetch_dependents_count(package[:name])
      if deps_count
        deps_result = score_dependents(deps_count)
        score += deps_result[:score]
        breakdown.concat(deps_result[:breakdown])
      end
      timings[:dependents] = ((Time.now - t3) * 1000).round(2)
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - dependents: #{timings[:dependents]}ms (score: #{score})" if ENV['PROFILE']
      
      return finalize(score, breakdown, 2) if score >= 70

      # Stage 3: GitHub signals
      t4 = Time.now
      gh = adapter.score_github(metadata)
      score += gh[:score]
      breakdown.concat(gh[:breakdown])
      timings[:github] = ((Time.now - t4) * 1000).round(2)
      puts "[PROFILE-TRUST] [#{Thread.current.object_id}] #{package[:name]} - github: #{timings[:github]}ms (score: #{score})" if ENV['PROFILE']

      finalize(score, breakdown, 3)
    end

    private

    def score_dependents(count)
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

    def not_found_result(package_name)
      {
        score: 0,
        level: 'NOT_FOUND',
        breakdown: [{ signal: 'existence', points: 0, reason: 'Package does not exist in registry' }],
        stage: 0
      }
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