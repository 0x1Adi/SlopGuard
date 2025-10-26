module SlopGuard
  class GitLabReporter
    VERSION = "15.0.0"
    
    def initialize(results, sbom_path)
      @results = results
      @sbom_path = sbom_path
      @scan_start = Time.now - 120
      @scan_end = Time.now
    end
    
    def generate
      {
        version: VERSION,
        scan: build_scan_metadata,
        vulnerabilities: build_vulnerabilities,
        dependency_files: build_dependency_files
      }
    end
    
    private
    
    def build_scan_metadata
      {
        scanner: {
          id: "slopguard",
          name: "SlopGuard"
        },
        analyzer: {
          id: "slopguard",
          name: "SlopGuard",
          vendor: {
            name: "SlopGuard"
          },
          version: "0.1.0"
        },
        type: "dependency_scanning",
        start_time: @scan_start.utc.iso8601,
        end_time: @scan_end.utc.iso8601,
        status: "success"
      }
    end
    
    def build_vulnerabilities
      @results[:packages]
        .reject { |pkg| pkg[:status] == 'VERIFIED' }
        .map { |pkg| build_vulnerability(pkg) }
    end
    
    def build_vulnerability(pkg)
      {
        id: generate_uuid(pkg),
        category: "dependency_scanning",
        name: build_name(pkg),
        message: build_message(pkg),
        description: build_description(pkg),
        severity: map_severity(pkg),
        solution: build_solution(pkg),
        scanner: {
          id: "slopguard",
          name: "SlopGuard"
        },
        location: {
          file: File.basename(@sbom_path),
          dependency: {
            package: {
              name: pkg[:package]
            },
            version: pkg[:version]
          }
        },
        identifiers: build_identifiers(pkg),
        links: build_links(pkg)
      }
    end
    
    def generate_uuid(pkg)
      # Generate deterministic UUID from package name + version + status
      data = "#{pkg[:package]}@#{pkg[:version]}:#{pkg[:status]}"
      digest = Digest::SHA256.hexdigest(data)
      
      # Convert to UUIDv5 format (8-4-4-4-12 hex format)
      [
        digest[0..7],
        digest[8..11],
        digest[12..15],
        digest[16..19],
        digest[20..31]
      ].join('-')
    end
    
    def build_name(pkg)
      case pkg[:status]
      when 'HALLUCINATED'
        "AI-Hallucinated Package: #{pkg[:package]}"
      when 'HIGH_RISK'
        if pkg[:anomalies]&.any? { |a| a[:type] == 'typosquat' }
          "Typosquatting Attack: #{pkg[:package]}"
        elsif pkg[:anomalies]&.any? { |a| a[:type] == 'namespace_squat' }
          "Namespace Squatting: #{pkg[:package]}"
        elsif pkg[:anomalies]&.any? { |a| a[:type] == 'homoglyph_attack' }
          "Homoglyph Attack: #{pkg[:package]}"
        else
          "High-Risk Package: #{pkg[:package]}"
        end
      when 'SUSPICIOUS'
        "Suspicious Package: #{pkg[:package]}"
      else
        "Security Issue: #{pkg[:package]}"
      end
    end
    
    def build_message(pkg)
      "#{build_name(pkg)} (trust score: #{pkg[:trust_score]}/100)"
    end
    
    def build_description(pkg)
      parts = []
      
      # Main issue description
      case pkg[:status]
      when 'HALLUCINATED'
        parts << "This package does not exist in the RubyGems registry. It may have been suggested by an AI coding assistant (ChatGPT, Claude, Copilot) that hallucinated a non-existent package name. Installing this package will fail unless an attacker has registered it with malicious code (slopsquatting attack)."
      when 'HIGH_RISK'
        parts << "This package exhibits multiple high-risk security indicators including low trust score (#{pkg[:trust_score]}/100) and severe security warnings. It may be a malicious package designed for supply chain attacks."
      when 'SUSPICIOUS'
        parts << "This package has a low trust score (#{pkg[:trust_score]}/100) and exhibits suspicious patterns. While not definitively malicious, it requires manual security review before use."
      end
      
      # Add trust breakdown
      if pkg[:breakdown]&.any?
        parts << "\n\nTrust Analysis:"
        pkg[:breakdown].each do |signal|
          parts << "- #{signal[:signal]}: #{signal[:points]} points (#{signal[:reason]})"
        end
      end
      
      # Add anomaly details
      if pkg[:anomalies]&.any?
        parts << "\n\nSecurity Warnings:"
        pkg[:anomalies].each do |anomaly|
          parts << "- [#{anomaly[:severity]}] #{anomaly[:type]}: #{anomaly[:evidence]}"
        end
      end
      
      parts.join("\n")
    end
    
    def map_severity(pkg)
      case pkg[:status]
      when 'HALLUCINATED'
        'Critical'
      when 'HIGH_RISK'
        critical_anomalies = pkg[:anomalies]&.select { |a| a[:severity] == 'CRITICAL' }
        critical_anomalies&.any? ? 'Critical' : 'High'
      when 'SUSPICIOUS'
        high_anomalies = pkg[:anomalies]&.select { |a| a[:severity] == 'HIGH' }
        high_anomalies&.any? ? 'High' : 'Medium'
      else
        'Low'
      end
    end
    
    def build_solution(pkg)
      case pkg[:status]
      when 'HALLUCINATED'
        "This package does not exist. Remove it from your dependencies immediately. Verify the correct package name with the framework documentation or search RubyGems.org directly. If you're using AI coding assistants, always verify suggested package names before installing."
      when 'HIGH_RISK'
        solutions = ["Remove this package immediately from your dependencies."]
        
        if pkg[:anomalies]&.any? { |a| a[:type] == 'typosquat' }
          target = pkg[:anomalies].find { |a| a[:type] == 'typosquat' }
          solutions << "This appears to be a typosquatting attack mimicking '#{target[:target_package]}'. Use the correct package name instead."
        end
        
        if pkg[:anomalies]&.any? { |a| a[:type] == 'ownership_change' }
          solutions << "The package maintainer recently changed. Review recent commits for malicious code before using."
        end
        
        solutions << "Rotate any credentials that may have been exposed if this package was already installed."
        solutions.join(" ")
      when 'SUSPICIOUS'
        "Conduct manual security review before using this package. Review the source code, check maintainer reputation, and verify the package serves its stated purpose. Consider using more established alternatives if available."
      else
        "Review package security before use."
      end
    end
    
    def build_identifiers(pkg)
      identifiers = []
      
      # Primary identifier: SlopGuard internal tracking
      identifiers << {
        type: "slopguard",
        name: "SLOPGUARD-#{pkg[:status]}-#{pkg[:package]}",
        value: "#{pkg[:status]}-#{pkg[:package]}",
        url: "https://github.com/aditya01933/slopguard##{pkg[:status].downcase}"
      }
      
      # Add CWE identifiers based on attack type
      if pkg[:anomalies]
        pkg[:anomalies].each do |anomaly|
          cwe = map_anomaly_to_cwe(anomaly[:type])
          if cwe
            identifiers << {
              type: "cwe",
              name: "CWE-#{cwe[:id]}",
              value: cwe[:id].to_s,
              url: "https://cwe.mitre.org/data/definitions/#{cwe[:id]}.html"
            }
          end
        end
      end
      
      # Ensure at least one identifier with valid URL
      if identifiers.empty? || identifiers.all? { |i| i[:url].nil? || i[:url].empty? }
        identifiers = [{
          type: "slopguard",
          name: "SLOPGUARD-SUPPLY-CHAIN",
          value: "supply-chain-risk",
          url: "https://github.com/aditya01933/slopguard"
        }]
      end
      
      identifiers
    end
    
    def map_anomaly_to_cwe(anomaly_type)
      # Map SlopGuard anomaly types to relevant CWE identifiers
      case anomaly_type
      when 'typosquat', 'namespace_squat', 'homoglyph_attack'
        { id: 506, name: "Embedded Malicious Code" }
      when 'download_inflation', 'suspicious_timing'
        { id: 912, name: "Hidden Functionality" }
      when 'ownership_change'
        { id: 494, name: "Download of Code Without Integrity Check" }
      when 'yanked_package'
        { id: 1395, name: "Dependency on Vulnerable Third-Party Component" }
      else
        { id: 1357, name: "Reliance on Reverse DNS Resolution for a Security-Critical Action" }
      end
    end
    
    def build_links(pkg)
      links = []
      
      # Add link to package on RubyGems (if it exists)
      unless pkg[:status] == 'HALLUCINATED'
        links << {
          url: "https://rubygems.org/gems/#{pkg[:package]}"
        }
      end
      
      # Add research links for attack types
      if pkg[:anomalies]&.any? { |a| a[:type] == 'typosquat' }
        links << {
          url: "https://blog.sonatype.com/typosquatting-attacks-on-software-package-managers"
        }
      end
      
      if pkg[:status] == 'HALLUCINATED'
        links << {
          url: "https://arxiv.org/abs/2406.10279"  # AI hallucination research paper
        }
      end
      
      links
    end
    
    def build_dependency_files
      # Extract all scanned packages grouped by their source file
      [{
        path: File.basename(@sbom_path),
        package_manager: "bundler",
        dependencies: @results[:packages].map do |pkg|
          {
            package: {
              name: pkg[:package]
            },
            version: pkg[:version]
          }
        end
      }]
    end
  end
end
