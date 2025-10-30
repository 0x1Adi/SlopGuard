require 'concurrent'

module SlopGuard
  class Scanner
    THREAD_POOL_SIZE = 3
    
    def initialize(sbom_path, http:, cache:)
      @sbom_path = sbom_path
      @http = http
      @cache = cache
      @trust_scorer = TrustScorer.new(http, cache)
    end

    def run
      packages = Parser.new(@sbom_path).parse
      
      if packages.empty?
        return {
          total: 0,
          verified: 0,
          suspicious: 0,
          high_risk: 0,
          not_found: 0,
          results: []
        }
      end

      # FIXED: Filter out unsupported ecosystems BEFORE processing
      supported_packages = packages.select do |pkg|
        AdapterFactory.supported?(pkg[:ecosystem])
      end
      
      # Log skipped packages for debugging
      skipped = packages.size - supported_packages.size
      if skipped > 0 && ENV['DEBUG']
        puts "[INFO] Skipped #{skipped} packages from unsupported ecosystems"
      end

      # Parallel processing with reduced thread pool
      pool = Concurrent::FixedThreadPool.new(THREAD_POOL_SIZE)
      futures = supported_packages.map do |pkg|
        Concurrent::Future.execute(executor: pool) do
          begin
            process_package(pkg)
          rescue StandardError => e
            # Handle exceptions gracefully with detailed error info
            error_msg = "#{e.class}: #{e.message}"
            $stderr.puts "[ERROR] Failed to process #{pkg[:name]}: #{error_msg}"
            $stderr.puts e.backtrace.first(5).join("\n") if ENV['DEBUG']
            
            {
              package: pkg,
              trust: { score: 0, level: 'ERROR', breakdown: [], stage: 0 },
              anomalies: [],
              action: 'WARN',
              error: error_msg
            }
          end
        end
      end

      # Collect results, filtering out any nils
      results = futures.map(&:value).compact
      pool.shutdown
      pool.wait_for_termination

      # Aggregate statistics
      {
        total: results.size,
        verified: results.count { |r| r[:action] == 'VERIFIED' },
        suspicious: results.count { |r| r[:action] == 'WARN' },
        high_risk: results.count { |r| r[:action] == 'BLOCK' },
        not_found: results.count { |r| r[:trust][:level] == 'NOT_FOUND' },
        results: results.sort_by { |r| [-severity_order(r[:action]), r[:package][:name]] }
      }
    end

    private

    def process_package(package)
      t1 = Time.now
      
      # Get ecosystem adapter
      adapter = AdapterFactory.create(package[:ecosystem], @http, @cache)
      
      # Calculate trust score
      trust = @trust_scorer.score(package)
      
      # Detect anomalies if trust is low
      anomalies = []
      if trust[:score] < 60 && trust[:level] != 'NOT_FOUND'
        # Fetch metadata for anomaly detection
        data = adapter.fetch_metadata(package[:name])
        if data
          anomalies = adapter.detect_anomalies(
            package[:name],
            data[:metadata],
            data[:versions]
          )
        end
      end
      
      # Apply anomaly penalties
      anomalies.each do |anomaly|
        case anomaly[:severity]
        when 'HIGH'
          trust[:score] -= 20
        when 'MEDIUM'
          trust[:score] -= 10
        when 'LOW'
          trust[:score] -= 5
        end
      end
      
      # Clamp score
      trust[:score] = [[trust[:score], 0].max, 100].min
      
      # Determine action
      action = determine_action(trust[:score], trust[:level], anomalies)
      
      elapsed = ((Time.now - t1) * 1000).round(2)
      puts "[PROFILE-SCAN] #{package[:name]} - Total: #{elapsed}ms" if ENV['PROFILE']
      
      {
        package: package,
        trust: trust,
        anomalies: anomalies,
        action: action
      }
    end

    def determine_action(score, level, anomalies)
      return 'NOT_FOUND' if level == 'NOT_FOUND'
      
      has_high_severity = anomalies.any? { |a| a[:severity] == 'HIGH' }
      
      if score >= 70
        'VERIFIED'
      elsif score >= 60 || !has_high_severity
        'WARN'
      else
        'BLOCK'
      end
    end

    def severity_order(action)
      case action
      when 'BLOCK' then 3
      when 'NOT_FOUND' then 2
      when 'WARN' then 1
      else 0
      end
    end
  end
end
