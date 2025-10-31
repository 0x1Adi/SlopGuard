require 'json'

module SlopGuard
  class Reporter
    def self.generate(results, sbom_path: nil, format: :text)
      case format
      when :json
        json_report(results)
      when :gitlab
        gitlab_report(results, sbom_path)
      else
        text_report(results)
      end
    end

    def self.format_text(results)
      text_report(results)
    end

    def self.json_report(results)
      JSON.pretty_generate(results)
    end
    
    def self.gitlab_report(results, sbom_path)
      reporter = GitLabReporter.new(results, sbom_path || 'sbom.json')
      JSON.pretty_generate(reporter.generate)
    end

    def self.text_report(results)
      lines = []
      lines << "=" * 80
      lines << "SLOPGUARD SCAN RESULTS"
      lines << "=" * 80
      lines << ""
      
      lines << "Total packages:     #{results[:total]}"
      lines << "✓ Verified:         #{results[:verified]}"
      lines << "⚠ Suspicious:       #{results[:suspicious]}"
      lines << "✗ High risk:        #{results[:high_risk]}"
      lines << "? Not found:        #{results[:not_found]}"
      
      # NEW: Add performance metrics if available
      if results[:metrics]
        m = results[:metrics]
        lines << ""
        lines << "PERFORMANCE:"
        lines << "Scan duration:      #{m[:scan_duration]}s"
        lines << "API calls:          #{m[:api_calls]}"
        lines << "Cache hit rate:     #{m[:cache_hit_rate]}%"
        lines << "Avg time/package:   #{m[:avg_time_per_package]}s"
      end
      
      lines << ""

      # Group by action
      by_action = results[:results].group_by { |r| r[:action] }
      
      # Show NOT_FOUND packages
      if by_action['NOT_FOUND']&.any?
        lines << "=" * 80
        lines << "❌ NON-EXISTENT PACKAGES (#{by_action['NOT_FOUND'].size})"
        lines << "=" * 80
        by_action['NOT_FOUND'].each do |r|
          lines << ""
          lines << "#{r[:package][:name]}@#{r[:package][:version]} [#{r[:package][:ecosystem]}]"
          lines << "  Status: Package does not exist in registry"
          lines << "  Action: BLOCK - Remove from dependencies"
        end
        lines << ""
      end

      # Show BLOCKED packages
      if by_action['BLOCK']&.any?
        lines << "=" * 80
        lines << "🚫 HIGH RISK PACKAGES (#{by_action['BLOCK'].size})"
        lines << "=" * 80
        by_action['BLOCK'].each do |r|
          lines << ""
          lines << "#{r[:package][:name]}@#{r[:package][:version]} [#{r[:package][:ecosystem]}]"
          lines << "  Trust Score: #{r[:trust][:score]}/100 (#{r[:trust][:level]})"
          lines << "  Action: BLOCK"
          
          if r[:trust][:breakdown].any?
            lines << "  Trust Breakdown:"
            r[:trust][:breakdown].each do |signal|
              lines << "    - #{signal[:signal]}: #{signal[:points]} pts (#{signal[:reason]})"
            end
          end
          
          if r[:anomalies].any?
            lines << "  ⚠️ Anomalies:"
            r[:anomalies].each do |anomaly|
              lines << "    - [#{anomaly[:severity]}] #{anomaly[:type]}: #{anomaly[:description]}"
            end
          end
        end
        lines << ""
      end

      # Show WARNED packages
      if by_action['WARN']&.any?
        lines << "=" * 80
        lines << "⚠️  SUSPICIOUS PACKAGES (#{by_action['WARN'].size})"
        lines << "=" * 80
        by_action['WARN'].each do |r|
          lines << ""
          lines << "#{r[:package][:name]}@#{r[:package][:version]} [#{r[:package][:ecosystem]}]"
          lines << "  Trust Score: #{r[:trust][:score]}/100 (#{r[:trust][:level]})"
          lines << "  Action: WARN"
          
          if r[:anomalies].any?
            lines << "  Warnings:"
            r[:anomalies].each do |anomaly|
              lines << "    - [#{anomaly[:severity]}] #{anomaly[:type]}: #{anomaly[:description]}"
            end
          end
        end
        lines << ""
      end

      # Show summary of verified packages
      if by_action['VERIFIED']&.any?
        lines << "=" * 80
        lines << "✅ VERIFIED PACKAGES (#{by_action['VERIFIED'].size})"
        lines << "=" * 80
        
        # Group by ecosystem
        by_ecosystem = by_action['VERIFIED'].group_by { |r| r[:package][:ecosystem] }
        
        by_ecosystem.each do |ecosystem, packages|
          lines << ""
          lines << "#{ecosystem.upcase}:"
          packages.sort_by { |r| r[:package][:name] }.each do |r|
            lines << "  ✓ #{r[:package][:name]}@#{r[:package][:version]} (trust: #{r[:trust][:score]})"
          end
        end
        lines << ""
      end

      lines << "=" * 80
      lines << "SUMMARY"
      lines << "=" * 80
      
      if results[:high_risk] > 0
        lines << "❌ FAILED: Found #{results[:high_risk]} high-risk packages"
      elsif results[:not_found] > 0
        lines << "⚠️  BLOCKED: Found #{results[:not_found]} hallucinated packages"
      elsif results[:suspicious] > 0
        lines << "⚠️  WARNING: Found #{results[:suspicious]} suspicious packages"
        lines << "   Action: Review warnings but safe to proceed"
      else
        lines << "✅ PASSED: All #{results[:verified]} packages verified"
      end

      lines.join("\n")
    end
  end
end
