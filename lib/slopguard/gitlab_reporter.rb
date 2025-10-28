require 'digest'
require 'json'

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
          version: "1.0.0"
        },
        type: "dependency_scanning",
        start_time: @scan_start.utc.iso8601,
        end_time: @scan_end.utc.iso8601,
        status: "success"
      }
    end
    
    def build_vulnerabilities
      @results[:results]
        .reject { |pkg| pkg[:action] == 'VERIFIED' }
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
              name: pkg[:package][:name]
            },
            version: pkg[:package][:version]
          }
        },
        identifiers: build_identifiers(pkg),
        links: build_links(pkg)
      }
    end
    
    def generate_uuid(pkg)
      # Generate deterministic UUID from package name + version + action
      data = "#{pkg[:package][:name]}@#{pkg[:package][:version]}:#{pkg[:action]}"
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
      case pkg[:action]
      when 'NOT_FOUND'
        "AI-Hallucinated Package: #{pkg[:package][:name]}"
      when 'BLOCK'
        if pkg[:anomalies]&.any? { |a| a[:type] == 'namespace_squat' }
          "Namespace Squatting: #{pkg[:package][:name]}"
        else
          "High-Risk Package: #{pkg[:package][:name]}"
        end
      when 'WARN'
        "Suspicious Package: #{pkg[:package][:name]}"
      else
        "Security Issue: #{pkg[:package][:name]}"
      end
    end
    
    def build_message(pkg)
      "#{build_name(pkg)} (trust score: #{pkg[:trust][:score]}/100)"
    end
    
    def build_description(pkg)
      parts = []
      
      # Main issue description
      case pkg[:action]
      when 'NOT_FOUND'
        parts << "This package does not exist in the #{pkg[:package][:ecosystem]} registry. It may have been suggested by an AI coding assistant (ChatGPT, Claude, Copilot) that hallucinated a non-existent package name."
      when 'BLOCK'
        parts << "This package has trust score #{pkg[:trust][:score]}/100 and exhibits high-risk security indicators. It may be a malicious package designed for supply chain attacks."
      when 'WARN'
        parts << "This package has trust score #{pkg[:trust][:score]}/100 and exhibits suspicious patterns."
      end
      
      # Add trust breakdown
      if pkg[:trust][:breakdown]&.any?
        parts << "\n\nTrust Analysis:"
        pkg[:trust][:breakdown].each do |signal|
          parts << "- #{signal[:signal]}: #{signal[:points]} points (#{signal[:reason]})"
        end
      end
      
      # Add anomaly details
      if pkg[:anomalies]&.any?
        parts << "\n\nSecurity Warnings:"
        pkg[:anomalies].each do |anomaly|
          parts << "- [#{anomaly[:severity]}] #{anomaly[:type]}: #{anomaly[:description]}"
        end
      end
      
      parts.join("\n")
    end
    
    def map_severity(pkg)
      case pkg[:action]
      when 'NOT_FOUND'
        'Critical'
      when 'BLOCK'
        critical_anomalies = pkg[:anomalies]&.select { |a| a[:severity] == 'HIGH' }
        critical_anomalies&.any? ? 'Critical' : 'High'
      when 'WARN'
        'Medium'
      else
        'Low'
      end
    end
    
    def build_solution(pkg)
      case pkg[:action]
      when 'NOT_FOUND'
        "Remove this package from your dependencies. Verify the correct package name with official documentation."
      when 'BLOCK'
        "Remove this package immediately. If needed, find alternatives with higher trust scores."
      when 'WARN'
        "Review this package manually. Check maintainer history, recent changes, and community reputation."
      else
        "Investigate this package before use."
      end
    end
    
    def build_identifiers(pkg)
      identifiers = []
      
      # Add package-specific identifier
      ecosystem = pkg[:package][:ecosystem]
      registry_url = case ecosystem
                     when 'ruby'
                       "https://rubygems.org/gems/#{pkg[:package][:name]}"
                     when 'python'
                       "https://pypi.org/project/#{pkg[:package][:name]}"
                     else
                       nil
                     end
      
      if registry_url && pkg[:action] != 'NOT_FOUND'
        identifiers << {
          type: "package",
          name: pkg[:package][:name],
          value: pkg[:package][:name],
          url: registry_url
        }
      end
      
      # Add CWE identifiers based on anomaly types
      if pkg[:anomalies]&.any?
        pkg[:anomalies].each do |anomaly|
          cwe = case anomaly[:type]
                when 'namespace_squat', 'typosquat'
                  { id: 'CWE-1357', name: 'Dependency Confusion', url: 'https://cwe.mitre.org/data/definitions/1357.html' }
                when 'download_inflation'
                  { id: 'CWE-506', name: 'Embedded Malicious Code', url: 'https://cwe.mitre.org/data/definitions/506.html' }
                else
                  nil
                end
          
          if cwe
            identifiers << {
              type: "cwe",
              name: cwe[:id],
              value: cwe[:id],
              url: cwe[:url]
            }
          end
        end
      end
      
      identifiers.uniq { |i| i[:value] }
    end
    
    def build_links(pkg)
      links = []
      
      # Add registry link if package exists
      if pkg[:action] != 'NOT_FOUND'
        ecosystem = pkg[:package][:ecosystem]
        url = case ecosystem
              when 'ruby'
                "https://rubygems.org/gems/#{pkg[:package][:name]}"
              when 'python'
                "https://pypi.org/project/#{pkg[:package][:name]}"
              end
        
        links << { url: url } if url
      end
      
      # Add research links
      links << { url: "https://github.com/aditya01933/SlopGuard" }
      
      links
    end
    
    def build_dependency_files
      [
        {
          path: @sbom_path,
          package_manager: "bundler",
          dependencies: []
        }
      ]
    end
  end
end
