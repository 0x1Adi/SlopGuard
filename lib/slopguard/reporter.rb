module SlopGuard
  class Reporter
    def self.generate(results, sbom_path: nil, format: :gitlab)
      case format
      when :json
        json_report(results)
      when :gitlab
        gitlab_report(results, sbom_path)
      else
        text_report(results)
      end
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
      lines << "=" * 60
      lines << "SLOPGUARD SCAN RESULTS"
      lines << "=" * 60
      
      summary = results[:summary]
      lines << "Total packages: #{summary[:total]}"
      lines << "Verified: #{summary[:verified]}"
      lines << "Suspicious: #{summary[:suspicious]}"
      lines << "High risk: #{summary[:high_risk]}"
      lines << "Hallucinated: #{summary[:hallucinated]}"
      lines << ""

      risky = results[:packages].select { |p| p[:status] != 'VERIFIED' }
      if risky.any?
        lines << "PACKAGES REQUIRING ATTENTION:"
        risky.each do |pkg|
          next if pkg[:status] == 'SUSPICIOUS'
          
          lines << ""
          lines << "#{pkg[:package]}@#{pkg[:version]} - #{pkg[:status]}"
          lines << "  Trust score: #{pkg[:trust_score]}/100 (#{pkg[:trust_level]})"
          lines << "  Action: #{pkg[:action]}"
          
          if pkg[:anomalies]&.any?
            lines << "  Warnings:"
            pkg[:anomalies].each do |anomaly|
              lines << "    - #{anomaly[:type]}: #{anomaly[:evidence]}"
            end
          end
        end
      else
        lines << "✓ All packages verified"
      end

      lines.join("\n")
    end
  end
end
