# frozen_string_literal: true

require 'json'
require 'package_url'

module SlopGuard
  class Parser
    MAX_FILE_SIZE = 5 * 1024 * 1024
    MAX_COMPONENTS = 5_000

    class ParseError < StandardError; end

    def initialize(sbom_path)
      @sbom_path = sbom_path
    end

    def parse
      validate_file!

      begin
        content = File.read(@sbom_path)
        data = JSON.parse(content,
                          symbolize_names:  true,
                          max_nesting:      50,
                          create_additions: false)
      rescue JSON::NestingError
        raise ParseError, 'SBOM JSON too deeply nested'
      rescue JSON::ParserError => e
        raise ParseError, "Invalid JSON: #{e.message}"
      rescue Errno::ENOENT
        raise ParseError, "File not found: #{@sbom_path}"
      rescue Errno::EACCES
        raise ParseError, "Permission denied: #{@sbom_path}"
      end

      validate_sbom_structure!(data)

      components = data[:components] || []

      raise ParseError, "Too many components: #{components.size} (max #{MAX_COMPONENTS})" if components.size > MAX_COMPONENTS

      packages = []
      components.each_with_index do |component, idx|
        pkg = parse_component(component)
        packages << pkg if pkg
      rescue StandardError => e
        warn "[WARN] Skipping component #{idx}: #{e.message}" if ENV['DEBUG']
      end

      packages.uniq { |p| "#{p[:ecosystem]}:#{p[:name]}:#{p[:version]}" }
    end

    private

    def validate_file!
      raise ParseError, "File does not exist: #{@sbom_path}" unless File.exist?(@sbom_path)
      raise ParseError, "File not readable: #{@sbom_path}" unless File.readable?(@sbom_path)

      file_size = File.size(@sbom_path)
      raise ParseError, "File too large: #{file_size} bytes (max #{MAX_FILE_SIZE})" if file_size > MAX_FILE_SIZE
      raise ParseError, 'File is empty' if file_size.zero?
    end

    def validate_sbom_structure!(data)
      raise ParseError, "Root must be object, got #{data.class}" unless data.is_a?(Hash)
      raise ParseError, "Unsupported format: #{data[:bomFormat]}" unless data[:bomFormat] == 'CycloneDX'
      raise ParseError, 'Missing specVersion' unless data[:specVersion]

      raise ParseError, "Components must be array, got #{data[:components].class}" if data[:components] && !data[:components].is_a?(Array)
    end

    def parse_component(component)
      raise ParseError, "Component must be object, got #{component.class}" unless component.is_a?(Hash)

      purl_string = component[:purl]
      return nil unless purl_string

      raise ParseError, "Invalid PURL: #{purl_string}" unless purl_string.is_a?(String)

      begin
        purl = PackageURL.parse(purl_string)
      rescue ArgumentError => e
        raise ParseError, "PURL parse error: #{e.message}"
      end

      ecosystem = map_purl_type(purl.type)
      return nil unless ecosystem

      name = build_package_name(purl)
      version = purl.version

      pkg = {
        name:      name,
        version:   version,
        ecosystem: ecosystem,
      }

      validate_package!(pkg)
      pkg
    end

    def map_purl_type(purl_type)
      case purl_type
      when 'gem'
        'ruby'
      when 'pypi'
        'python'
      when 'golang'
        'golang'
      when 'npm'
        'npm'
      end
    end

    def build_package_name(purl)
      if purl.namespace && !purl.namespace.empty?
        case purl.type
        when 'golang'
          "#{purl.namespace}/#{purl.name}"
        when 'npm'
          "@#{purl.namespace}/#{purl.name}"
        when 'maven'
          "#{purl.namespace}:#{purl.name}"
        else
          purl.name
        end
      else
        purl.name
      end
    end

    def validate_package!(pkg)
      raise ParseError, 'Package name empty' if pkg[:name].nil? || pkg[:name].empty?
      raise ParseError, 'Package version empty' if pkg[:version].nil? || pkg[:version].empty?
      raise ParseError, 'Package ecosystem empty' if pkg[:ecosystem].nil? || pkg[:ecosystem].empty?
      raise ParseError, "Name too long: #{pkg[:name].length} chars" if pkg[:name].length > 200
      raise ParseError, "Version too long: #{pkg[:version].length} chars" if pkg[:version].length > 50
    end
  end
end
