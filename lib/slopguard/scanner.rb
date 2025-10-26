module SlopGuard
  class Scanner
    MAX_SBOM_SIZE = 10_000_000  # 10MB limit
    STREAMING_THRESHOLD = 2000

    def initialize(sbom_path, options = {})
      validate_input(sbom_path)
      
      @sbom_path = sbom_path
      @options = options
      @allowlist = load_allowlist(options[:allowlist])
      @cache = Cache.new
      @http = HttpClient.new(github_token: options[:github_token])  # Pass token
      @trust_scorer = TrustScorer.new(@http, @cache)
      @anomaly_detector = AnomalyDetector.new(@http, @cache)
    end


    def run
      @scan_start_time = Time.now
      
      packages = Parser.new(@sbom_path).parse
      raise "No packages found in SBOM" if packages.empty?
      
      packages.each_with_index do |pkg, idx|
      end
      
      puts "Found #{packages.size} packages to scan" unless @options[:quiet]
      puts "Found #{packages.size} packages to scan" unless @options[:quiet]
      
      result = if packages.size > STREAMING_THRESHOLD
                 process_streaming(packages)
               else
                 process_parallel(packages)
               end
      
      @scan_end_time = Time.now
      elapsed = @scan_end_time - @scan_start_time
      
      if ENV['PROFILE']
        puts "\n" + "="*60
        puts "PERFORMANCE SUMMARY"
        puts "="*60
        puts "Total packages: #{packages.size}"
        puts "Total time: #{elapsed.round(2)}s"
        puts "Avg per package: #{(elapsed / packages.size * 1000).round(2)}ms"
        puts "="*60
      end
      
      result.merge(sbom_path: @sbom_path)
    end

    private

    def validate_input(path)
      raise "File does not exist: #{path}" unless File.exist?(path)
      raise "File not readable: #{path}" unless File.readable?(path)
      raise "File too large (>10MB): #{path}" if File.size(path) > MAX_SBOM_SIZE
      raise "Not a JSON file: #{path}" unless path.end_with?('.json')
    end

    def load_allowlist(path)
      return [] unless path && File.exist?(path)
      File.readlines(path).map(&:strip).reject(&:empty?)
    end

    def process_parallel(packages)
      
      pool = Concurrent::FixedThreadPool.new(10)
      futures = packages.map do |pkg|
        Concurrent::Future.execute(executor: pool) { verify(pkg) }
      end

      
      results = []
      github_rate_limit_hit = false
      
      futures.each_with_index do |future, idx|
        begin
          val = future.value
          results << val if val
        rescue => e
          # Check if it's a GitHub rate limit error
          if e.message.include?('GitHub API rate limit exceeded')
            github_rate_limit_hit = true
            puts "\n[WARN] GitHub API rate limit exceeded at package #{idx + 1}/#{packages.size}"
            puts "[WARN] #{e.message}"
            puts "[WARN] Returning partial results for #{results.size} packages scanned before rate limit\n"
            break  # Stop processing remaining packages
          end
          
          puts e.backtrace.first(3).join("\n") if ENV['DEBUG']
        end
      end
      
      
      pool.shutdown
      pool.wait_for_termination
      @http.close_all

      summary = summarize(results)
      
      if github_rate_limit_hit
        summary[:warning] = "GitHub API rate limit exceeded. Results are incomplete (#{results.size}/#{packages.size} packages scanned). Set GITHUB_TOKEN environment variable for 5000 requests/hour limit."
      end

      { packages: results, summary: summary }
    end

    def process_streaming(packages)
      results = []
      batch_size = 500
      
      packages.each_slice(batch_size) do |batch|
        pool = Concurrent::FixedThreadPool.new(10)
        futures = batch.map do |pkg|
          Concurrent::Future.execute(executor: pool) { verify(pkg) }
        end

        batch_results = futures.map(&:value).compact
        results.concat(batch_results)
        
        pool.shutdown
        pool.wait_for_termination
        
        puts "Processed #{results.size}/#{packages.size} packages..."
        GC.start  # Force garbage collection between batches
      end

      @http.close_all
      { packages: results, summary: summarize(results) }
    end

    def verify(package)
      begin
        timings = {}
        total_start = Time.now
        
        puts "[DEBUG-VERIFY] Starting verify for #{package[:name]}" if ENV['DEBUG']
        
        # Skip allowlisted packages
        if @allowlist.include?(package[:name])
          puts "[DEBUG-VERIFY] Package #{package[:name]} is allowlisted" if ENV['DEBUG']
          return {
            package: package[:name],
            version: package[:version],
            status: 'VERIFIED',
            trust_score: 100,
            trust_level: 'ALLOWLISTED',
            action: 'ALLOW',
            reason: 'Package is allowlisted'
          }
        end

        # 1. Metadata fetch
        t1 = Time.now
        meta = @http.get("https://rubygems.org/api/v1/gems/#{package[:name]}.json")
        timings[:metadata_fetch] = ((Time.now - t1) * 1000).round(2)
        puts "[PROFILE] [#{Thread.current.object_id}] #{package[:name]} - Metadata: #{timings[:metadata_fetch]}ms" if ENV['PROFILE']
        
        unless meta
          return {
            package: package[:name],
            version: package[:version],
            status: 'HALLUCINATED',
            trust_score: 0,
            action: 'BLOCK',
            reason: 'Package not found in RubyGems registry'
          }
        end

        # 2. Trust scoring
        t2 = Time.now
        trust = @trust_scorer.score(package, meta)
        timings[:trust_scoring] = ((Time.now - t2) * 1000).round(2)
        puts "[PROFILE] [#{Thread.current.object_id}] #{package[:name]} - Trust: #{timings[:trust_scoring]}ms (score: #{trust[:score]}, stage: #{trust[:stage]})" if ENV['PROFILE']
        
        # 3. Anomaly detection with validation
        t3 = Time.now
        raw_anomalies = case trust[:score]
                        when 80..100
                          []
                        when 60..79
                          result = @anomaly_detector.detect(package, meta, trust)
                          # Validate it's an array
                          unless result.is_a?(Array)
                            puts "[ERROR] Anomaly detector returned non-array: #{result.class}" if ENV['DEBUG']
                            []
                          else
                            result.select { |a| a.is_a?(Hash) && (a[:severity] == 'CRITICAL' || a[:severity] == 'HIGH') }
                          end
                        else
                          result = @anomaly_detector.detect(package, meta, trust)
                          # Validate it's an array
                          unless result.is_a?(Array)
                            puts "[ERROR] Anomaly detector returned non-array: #{result.class}" if ENV['DEBUG']
                            []
                          else
                            result.select { |a| a.is_a?(Hash) }
                          end
                        end
        
        # Ensure anomalies is always an array of hashes
        anomalies = raw_anomalies.is_a?(Array) ? raw_anomalies : []
        
        timings[:anomaly_detection] = ((Time.now - t3) * 1000).round(2)
        puts "[PROFILE] [#{Thread.current.object_id}] #{package[:name]} - Anomalies: #{timings[:anomaly_detection]}ms (found: #{anomalies.size})" if ENV['PROFILE']
        
        total_time = ((Time.now - total_start) * 1000).round(2)
        puts "[PROFILE] [#{Thread.current.object_id}] #{package[:name]} - TOTAL: #{total_time}ms" if ENV['PROFILE']
        
        # Calculate final score with penalties/bonuses
        penalties = anomalies.sum { |a| a[:penalty] || 0 }
        bonuses = anomalies.sum { |a| a[:bonus] || 0 }
        final_score = [[trust[:score] + penalties + bonuses, 0].max, 100].min

        # Determine status
        critical_anomalies = anomalies.select { |a| a[:severity] == 'CRITICAL' }
        high_severity_anomalies = anomalies.select { |a| a[:severity] == 'HIGH' }

        status = if critical_anomalies.any?
                   'HIGH_RISK'
                 elsif final_score < 30 && high_severity_anomalies.any?
                   'HIGH_RISK'
                 elsif final_score < 50 || anomalies.any?
                   'SUSPICIOUS'
                 else
                   'VERIFIED'
                 end

        action = case status
                 when 'HIGH_RISK' then 'BLOCK'
                 when 'SUSPICIOUS' then 'WARN'
                 else 'ALLOW'
                 end

        {
          package: package[:name],
          version: package[:version],
          status: status,
          trust_score: final_score,
          trust_level: trust[:level],
          breakdown: trust[:breakdown],
          anomalies: anomalies,
          action: action,
          reason: determine_reason(status, trust, anomalies)
        }
        
      rescue SlopGuard::HttpClient::GitHubRateLimitError => e
        # Re-raise GitHub rate limit to be caught by process_parallel
        raise
      rescue => e
        puts "[ERROR] verify(#{package[:name]}) crashed: #{e.message}" if ENV['DEBUG']
        puts e.backtrace.first(5).join("\n") if ENV['DEBUG']
        
        return {
          package: package[:name],
          version: package[:version],
          status: 'ERROR',
          trust_score: 0,
          action: 'WARN',
          reason: "Scan error: #{e.message}"
        }
      end
    end

    def determine_reason(status, trust, anomalies)
      case status
      when 'HIGH_RISK'
        critical = anomalies.find { |a| a[:severity] == 'CRITICAL' }
        return critical[:evidence] if critical
        "Low trust (#{trust[:score]}) + security warnings"
      when 'SUSPICIOUS'
        "Trust score #{trust[:score]} with #{anomalies.size} warning(s)"
      else
        "All checks passed"
      end
    end

    def summarize(results)
      results.compact!
      {
        total: results.size,
        verified: results.count { |r| r[:status] == 'VERIFIED' },
        suspicious: results.count { |r| r[:status] == 'SUSPICIOUS' },
        high_risk: results.count { |r| r[:status] == 'HIGH_RISK' },
        hallucinated: results.count { |r| r[:status] == 'HALLUCINATED' },
        errors: results.count { |r| r[:status] == 'ERROR' }
      }
    end
  end
end
