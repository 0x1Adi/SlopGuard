# frozen_string_literal: true

require 'concurrent'

module SlopGuard
  class Scanner
    THREAD_POOL_SIZE = 3

    def initialize(sbom_path, http:, cache:)
      @sbom_path = sbom_path
      @http = http
      @cache = cache
      @trust_scorer = TrustScorer.new(http, cache)
      @start_time = Time.now
    end

    def run
      packages = Parser.new(@sbom_path).parse

      if packages.empty?
        return {
          total:      0,
          verified:   0,
          suspicious: 0,
          high_risk:  0,
          not_found:  0,
          results:    [],
          metrics:    build_metrics(0),
        }
      end

      supported_packages = packages.select do |pkg|
        AdapterFactory.supported?(pkg[:ecosystem])
      end

      skipped_packages = packages - supported_packages

      if skipped_packages.any?
        warn "\n⚠️  WARNING: Skipped #{skipped_packages.size} packages from unsupported ecosystems:"

        by_ecosystem = skipped_packages.group_by { |p| p[:ecosystem] }
        by_ecosystem.each do |ecosystem, pkgs|
          warn "  - #{ecosystem}: #{pkgs.size} packages"
        end

        warn "  Supported: #{AdapterFactory.supported_ecosystems.join(', ')}"
        warn "  See ADDING_ECOSYSTEMS.md to add support\n"
      end

      pool = Concurrent::FixedThreadPool.new(THREAD_POOL_SIZE)
      futures = supported_packages.map do |pkg|
        Concurrent::Future.execute(executor: pool) do
          process_package(pkg)
        rescue StandardError => e
          error_msg = "#{e.class}: #{e.message}"
          warn "[ERROR] Failed to process #{pkg[:name]}: #{error_msg}"
          warn e.backtrace.first(5).join("\n") if ENV['DEBUG']

          {
            package:   pkg,
            trust:     { score: 0, level: 'ERROR', breakdown: [], stage: 0 },
            anomalies: [],
            action:    'WARN',
            error:     error_msg,
          }
        end
      end

      results = futures.map do |future|
        future.value(120) # 2 minute timeout per package
      rescue Concurrent::TimeoutError
        warn '[ERROR] Package scan timed out'
        nil
      end.compact

      pool.shutdown
      unless pool.wait_for_termination(300) # 5 minute total timeout
        pool.kill
        raise 'Scanner thread pool did not terminate cleanly'
      end

      {
        total:      results.size,
        verified:   results.count { |r| r[:action] == 'VERIFIED' },
        suspicious: results.count { |r| r[:action] == 'WARN' },
        high_risk:  results.count { |r| r[:action] == 'BLOCK' },
        not_found:  results.count { |r| r[:trust][:level] == 'NOT_FOUND' },
        results:    results.sort_by { |r| [-severity_order(r[:action]), r[:package][:name]] },
        metrics:    build_metrics(results.size),
      }
    end

    private

    def process_package(package)
      t1 = Time.now

      adapter = AdapterFactory.create(package[:ecosystem], @http, @cache)

      trust = @trust_scorer.score(package)

      anomalies = []
      if trust[:score] < 60 && trust[:level] != 'NOT_FOUND'

        data = adapter.fetch_metadata(package[:name])
        if data
          anomalies = adapter.detect_anomalies(
            package[:name],
            data[:metadata],
            data[:versions]
          )
        end
      end

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

      trust[:score] = trust[:score].clamp(0, 100)

      action = determine_action(trust[:score], trust[:level], anomalies)

      elapsed = ((Time.now - t1) * 1000).round(2)
      puts "[PROFILE-SCAN] #{package[:name]} - Total: #{elapsed}ms" if ENV['PROFILE']

      {
        package:   package,
        trust:     trust,
        anomalies: anomalies,
        action:    action,
      }
    end

    def determine_action(score, level, anomalies)
      return 'NOT_FOUND' if level == 'NOT_FOUND'

      has_high_severity = anomalies.any? { |a| a[:severity] == 'HIGH' }

      if score >= 60
        'VERIFIED'

      elsif score < 40 || has_high_severity
        'WARN'
      else

        'VERIFIED'
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

    def build_metrics(package_count)
      scan_duration = Time.now - @start_time

      {
        scan_duration:        scan_duration.round(2),
        api_calls:            @http.api_call_count,
        cache_hit_rate:       @cache.hit_rate,
        avg_time_per_package: package_count.positive? ? (scan_duration / package_count).round(3) : 0,
      }
    end
  end
end
