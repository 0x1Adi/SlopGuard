module SlopGuard
  class AnomalyDetector
    def initialize(http, cache)
      @http = http
      @cache = cache
    end

    def detect(package, metadata, trust)
      timings = {}
      all_anomalies = []
      
      checks = [
        [:check_yanked, metadata],
        [:check_missing_mfa, metadata],
        [:check_version_spike, package, metadata],
        [:check_download_inflation, package, metadata],
        [:check_namespace_squat, package, metadata],
        [:check_ownership_change, package, metadata],
        [:check_typosquat, package, metadata],
        [:check_homoglyph, package[:name]],
        [:check_suspicious_timing, metadata]
      ]
      
      checks.each do |check_data|
        method_name = check_data[0]
        args = check_data[1..-1]
        
        start = Time.now
        result = send(method_name, *args)
        elapsed = ((Time.now - start) * 1000).round(2)
        timings[method_name] = elapsed
        
        puts "[PROFILE-ANOMALY] [#{Thread.current.object_id}] #{package[:name]} - #{method_name}: #{elapsed}ms" if ENV['PROFILE']
        
        all_anomalies << result if result
      end
      
      if ENV['PROFILE']
        total = timings.values.sum
        puts "[PROFILE-ANOMALY] [#{Thread.current.object_id}] #{package[:name]} - ANOMALY TOTAL: #{total.round(2)}ms"
        
        # Show slowest checks
        slowest = timings.sort_by { |k, v| -v }.first(3)
        slowest.each do |method, time|
          puts "[PROFILE-ANOMALY] [#{Thread.current.object_id}] #{package[:name]} - SLOW: #{method} = #{time}ms"
        end
      end
      
      all_anomalies.compact
    end

    private

    def check_version_spike(package, metadata)  # Takes 2 args, not 1
      cache_key = "versions:#{package[:name]}"
      versions = @cache.get(cache_key, ttl: 604800)
      
      return nil unless versions && versions.size > 5
      
      recent = versions.last(10).select { |v| v[:created_at] }
      return nil if recent.size < 3
      
      timestamps = recent.map { |v| Time.parse(v[:created_at]) }
      
      one_day_ago = Time.now - 86400
      recent_count = timestamps.count { |t| t > one_day_ago }
      
      if recent_count >= 5
        return {
          type: 'version_spike',
          severity: 'HIGH',
          penalty: -20,
          confidence: 85,
          evidence: "#{recent_count} versions published in last 24 hours"
        }
      end
      
      week_ago = Time.now - (7 * 86400)
      week_count = timestamps.count { |t| t > week_ago }
      
      if week_count >= 10
        {
          type: 'rapid_versioning',
          severity: 'MEDIUM',
          penalty: -10,
          confidence: 70,
          evidence: "#{week_count} versions in 7 days"
        }
      end
    end

    def check_yanked(meta)
      return nil unless meta[:yanked]
      
      {
        type: 'yanked_package',
        severity: 'CRITICAL',
        penalty: -100,
        confidence: 100,
        evidence: "Package yanked (removed) from RubyGems"
      }
    end

    def check_missing_mfa(meta)
      downloads = meta[:downloads].to_i
      has_mfa = meta.dig(:metadata, :rubygems_mfa_required) == 'true'
      
      # Only warn on mega-popular packages (>100M)
      if downloads > 100_000_000 && !has_mfa
        {
          type: 'missing_mfa',
          severity: 'LOW',
          penalty: -2,
          confidence: 40,
          evidence: "Critical infrastructure without MFA protection"
        }
      end
    end

    def check_download_inflation(package, meta)
      downloads = meta[:downloads].to_i
      
      return nil if downloads > 50_000_000
      
      # Try cache first - already fetched by trust scorer
      cache_key = "versions:#{package[:name]}"
      versions = @cache.get(cache_key, ttl: 604800)
      
      # If not cached, fetch (shouldn't happen often)
      unless versions
        data = @http.get("https://rubygems.org/api/v1/versions/#{package[:name]}.json")
        return nil unless data
        versions = data
        @cache.set(cache_key, versions, ttl: 604800)
      end

      return nil if versions.empty?
      
      valid_versions = versions.select { |v| v[:created_at] }
      return nil if valid_versions.empty?
      
      oldest = valid_versions.min_by { |v| Time.parse(v[:created_at]) }
      age_days = (Time.now - Time.parse(oldest[:created_at])) / 86400
      return nil if age_days < 7

      expected = age_days * 1000.0
      ratio = (downloads.to_f / expected).round

      if ratio > 100 && age_days < 30
        {
          type: 'download_inflation',
          severity: 'HIGH',
          penalty: -30,
          evidence: "#{downloads} downloads in #{age_days.to_i} days (#{ratio.to_i}x expected)"
        }
      elsif ratio > 50 && age_days < 14
        {
          type: 'rapid_growth',
          severity: 'MEDIUM',
          penalty: -15,
          evidence: "Unusual growth for very new package"
        }
      end
    end

    def check_ownership_change(package, meta)
      history_key = "history:#{package[:name]}"
      previous = @cache.get(history_key, ttl: 2592000)
      
      current_author = meta[:authors] || 'unknown'
      
      @cache.set(history_key, {
        author: current_author,
        scanned_at: Time.now.to_i
      }, ttl: 2592000)
      
      return nil unless previous
      
      old_author = previous[:author]
      return nil if old_author == current_author
      
      downloads = meta[:downloads].to_i
      severity = case downloads
                 when 0..100_000 then 'LOW'
                 when 100_001..1_000_000 then 'MEDIUM'
                 when 1_000_001..10_000_000 then 'HIGH'
                 else 'CRITICAL'
                 end
      
      penalty = case severity
                when 'CRITICAL' then -40
                when 'HIGH' then -20
                else -10
                end
      
      days_since = (Time.now.to_i - previous[:scanned_at]) / 86400
      
      {
        type: 'ownership_change',
        severity: severity,
        penalty: penalty,
        confidence: 80,
        evidence: "Author changed from #{old_author} to #{current_author}",
        days_since_last_scan: days_since,
        recommendation: "REVIEW: Check recent commits for malicious code"
      }
    end

    def check_typosquat(package, meta)
      # Use class-level mutex for popular gems (shared across all detector instances)
      @@popular_mutex ||= Mutex.new
      
      popular = @@popular_mutex.synchronize do
        # Check cache inside mutex
        cached = @cache.get('popular:ruby', ttl: 604800)
        return cached if cached
        
        # Only ONE thread fetches, others wait here
        puts "[PROFILE-TYPO] #{package[:name]} - Fetching popular gems (cache miss)..." if ENV['PROFILE']
        t_start = Time.now
        
        # Just fetch top 3, not 7
        known_popular = %w[rails rake bundler]
        
        result = known_popular.map do |name|
          data = @http.get("https://rubygems.org/api/v1/gems/#{name}.json")
          next unless data
          { name: data[:name], downloads: data[:downloads] }
        end.compact
        
        t_elapsed = ((Time.now - t_start) * 1000).round(2)
        puts "[PROFILE-TYPO] #{package[:name]} - Fetched #{result.size} gems in #{t_elapsed}ms" if ENV['PROFILE']
        
        # Cache it
        @cache.set('popular:ruby', result, ttl: 604800)
        result
      end

      return nil unless popular && popular.any?

      name = package[:name]
      current_dl = meta[:downloads].to_i
      
      popular.each do |target|
        dist = levenshtein(name, target[:name])
        if dist == 1
          adoption_ratio = current_dl.to_f / target[:downloads]
          if adoption_ratio < 0.001
            return {
              type: 'typosquat',
              severity: 'HIGH',
              penalty: -30,
              confidence: 90,
              evidence: "1-char from '#{target[:name]}' (#{target[:downloads]} downloads) but only #{current_dl} downloads",
              target_package: target[:name],
              edit_distance: dist,
              adoption_ratio: adoption_ratio
            }
          end
        end
      end
      nil
    end

    def check_homoglyph(name)
      confusables = [
        ['0', 'O'], ['1', 'l'], ['1', 'I'], ['rn', 'm'], ['vv', 'w']
      ]
      
      popular = @cache.get('popular:ruby', ttl: 604800) || []
      popular_names = popular.map { |p| p[:name] }
      
      confusables.each do |bad_char, good_char|
        if name.include?(bad_char)
          test_name = name.gsub(bad_char, good_char)
          if popular_names.include?(test_name)
            return {
              type: 'homoglyph_attack',
              severity: 'HIGH',
              penalty: -35,
              confidence: 95,
              evidence: "Contains '#{bad_char}' which resembles '#{good_char}' in #{test_name}",
              target_package: test_name,
              confusable_pair: [bad_char, good_char]
            }
          end
        end
      end
      nil
    end

    def check_namespace_squat(package, meta)
      parts = package[:name].split(/[-_]/)
      return nil if parts.size == 1

      base = parts[0]
      base_meta = @http.get("https://rubygems.org/api/v1/gems/#{base}.json")
      return nil unless base_meta
      return nil if base_meta[:downloads].to_i < 100_000

      current_dl = meta[:downloads].to_i
      base_dl = base_meta[:downloads].to_i

      if current_dl < 1000
        {
          type: 'namespace_squat',
          severity: 'HIGH',
          penalty: -25,
          evidence: "Uses '#{base}' namespace (#{base_dl} downloads) but only #{current_dl} downloads",
          base_package: base
        }
      elsif current_dl < (base_dl * 0.01)
        {
          type: 'namespace_squat',
          severity: 'MEDIUM',
          penalty: -15,
          evidence: "Uses popular namespace but minimal adoption vs base"
        }
      else
        {
          type: 'verified_namespace',
          bonus: 15,
          evidence: "Significant adoption for #{base} plugin"
        }
      end
    end

    def check_suspicious_timing(meta)
      created_str = meta[:version_created_at]
      return nil unless created_str
      
      created = Time.parse(created_str)
      hour = created.hour
      day = created.wday
      
      is_weekend = [0, 6].include?(day)
      is_night = hour < 6 || hour > 22
      
      if is_weekend && is_night
        {
          type: 'suspicious_timing',
          severity: 'LOW',
          penalty: -5,
          confidence: 40,
          evidence: "Version published at #{created.strftime('%Y-%m-%d %H:%M')} (weekend night)"
        }
      end
    end

    def levenshtein(s, t)
      m = s.length
      n = t.length
      return m if n == 0
      return n if m == 0

      d = Array.new(m + 1) { Array.new(n + 1) }

      (0..m).each { |i| d[i][0] = i }
      (0..n).each { |j| d[0][j] = j }

      (1..n).each do |j|
        (1..m).each do |i|
          cost = s[i - 1] == t[j - 1] ? 0 : 1
          d[i][j] = [
            d[i - 1][j] + 1,
            d[i][j - 1] + 1,
            d[i - 1][j - 1] + cost
          ].min
        end
      end

      d[m][n]
    end
  end
end
