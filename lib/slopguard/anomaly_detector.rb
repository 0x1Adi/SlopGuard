module SlopGuard
  class AnomalyDetector
    def initialize(http, cache)
      @http = http
      @cache = cache
    end

    def detect(package, metadata, trust)
      [
        check_download_inflation(package, metadata),
        check_namespace_squat(package, metadata),
        check_ownership_change(package, metadata),
        check_typosquat(package, metadata),
        check_homoglyph(package[:name]),
        check_suspicious_timing(metadata)
      ].compact
    end

    private

    def check_download_inflation(package, meta)
      downloads = meta[:downloads].to_i
      
      # Skip check for packages with very high downloads (established packages)
      return nil if downloads > 50_000_000
      
      cache_key = "versions:#{package[:name]}"
      versions = @cache.get(cache_key, ttl: 604800)
      
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
      return nil if age_days < 7  # Only check packages > 1 week old

      # More realistic baseline: 1000 downloads/day for legit packages
      expected = age_days * 1000
      ratio = downloads / [expected, 1].max

      # Only flag if ratio is extreme AND package is new
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
      popular = @cache.get('popular:ruby', ttl: 604800)
      unless popular
        data = @http.get('https://rubygems.org/api/v1/downloads/top.json')
        return nil unless data && data.is_a?(Array)
        
        popular = data.first(20).map { |p| { name: p[:name], downloads: p[:downloads] } }
        @cache.set('popular:ruby', popular, ttl: 604800)
      end

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
