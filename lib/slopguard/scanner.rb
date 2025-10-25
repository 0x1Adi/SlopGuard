module SlopGuard
  class Scanner
    def initialize(sbom_path, options = {})
      @sbom_path = sbom_path
      @options = options
      @cache = Cache.new
      @http = HttpClient.new
      @trust_scorer = TrustScorer.new(@http, @cache)
      @anomaly_detector = AnomalyDetector.new(@http, @cache)
    end

    def run
      packages = Parser.new(@sbom_path).parse
      
      pool = Concurrent::FixedThreadPool.new(10)
      futures = packages.map do |pkg|
        Concurrent::Future.execute(executor: pool) { verify(pkg) }
      end

      results = futures.map(&:value)
      pool.shutdown
      pool.wait_for_termination

      { packages: results, summary: summarize(results) }
    end

    private

    def verify(package)
      meta = @http.get("https://rubygems.org/api/v1/gems/#{package[:name]}.json")
      
      unless meta
        return {
          package: package[:name],
          version: package[:version],
          status: 'HALLUCINATED',
          trust_score: 0,
          action: 'BLOCK'
        }
      end

      trust = @trust_scorer.score(package, meta)
      anomalies = @anomaly_detector.detect(package, meta, trust)
      
      penalties = anomalies.sum { |a| a[:penalty] || 0 }
      bonuses = anomalies.sum { |a| a[:bonus] || 0 }
      final_score = [[trust[:score] + penalties + bonuses, 0].max, 100].min

      status = if final_score < 40 && anomalies.any? { |a| a[:severity] == 'HIGH' }
                 'HIGH_RISK'
               elsif final_score < 60 || anomalies.any?
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
        action: action
      }
    rescue Errno::ENOENT, JSON::ParserError => e
      {
        package: package[:name],
        version: package[:version],
        status: 'ERROR',
        trust_score: 0,
        action: 'BLOCK',
        error: "#{e.class}: #{e.message}"
      }
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
