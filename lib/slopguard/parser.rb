# frozen_string_literal: true

require 'json'

module SlopGuard
  class Parser
    MAX_FILE_SIZE = 50 * 1024 * 1024
    MAX_COMPONENTS = 10_000

    class ParseError < StandardError; end

    def initialize(sbom_path)
      @sbom_path = sbom_path
    end

    def parse
      validate_file!

      begin
        content = File.read(@sbom_path)
        data = JSON.parse(content, symbolize_names: true)
      rescue JSON::ParserError => e
        raise ParseError, "Invalid JSON in SBOM: #{e.message}"
      rescue Errno::ENOENT
        raise ParseError, "SBOM file not found: #{@sbom_path}"
      rescue Errno::EACCES
        raise ParseError, "Permission denied reading SBOM: #{@sbom_path}"
      end

      validate_sbom_structure!(data)

      components = data[:components] || []

      if components.size > MAX_COMPONENTS
        raise ParseError, "SBOM contains too many components (#{components.size}), max is #{MAX_COMPONENTS}"
      end

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
      raise ParseError, "SBOM file does not exist: #{@sbom_path}" unless File.exist?(@sbom_path)

      raise ParseError, "SBOM file is not readable: #{@sbom_path}" unless File.readable?(@sbom_path)

      file_size = File.size(@sbom_path)
      raise ParseError, "SBOM file too large: #{file_size} bytes (max #{MAX_FILE_SIZE})" if file_size > MAX_FILE_SIZE

      raise ParseError, 'SBOM file is empty' if file_size.zero?
    end

    def validate_sbom_structure!(data)
      raise ParseError, "SBOM root must be an object, got #{data.class}" unless data.is_a?(Hash)

      raise ParseError, "Unsupported BOM format: #{data[:bomFormat]}" unless data[:bomFormat] == 'CycloneDX'

      raise ParseError, 'Missing specVersion in SBOM' unless data[:specVersion]

      if data[:components] && !data[:components].is_a?(Array)
        raise ParseError, "Components must be an array, got #{data[:components].class}"
      end
    end

    def parse_component(component)
      raise ParseError, "Component must be an object, got #{component.class}" unless component.is_a?(Hash)

      purl = component[:purl]
      return nil unless purl

      raise ParseError, "Invalid PURL format: #{purl}" unless purl.is_a?(String) && purl.start_with?('pkg:')

      pkg = parse_purl(purl)
      return nil unless pkg

      validate_package!(pkg)

      pkg
    end

    def parse_purl(purl)
      case purl
      when %r{^pkg:gem/([^@]+)@(.+)$}
        { name: sanitize_name(::Regexp.last_match(1)), version: sanitize_version(::Regexp.last_match(2)),
ecosystem: 'ruby' }
      when %r{^pkg:pypi/([^@]+)@(.+)$}
        { name: sanitize_name(::Regexp.last_match(1)), version: sanitize_version(::Regexp.last_match(2)),
ecosystem: 'python' }
      when %r{^pkg:golang/([^@]+)@(.+)$}
        { name: sanitize_name(::Regexp.last_match(1)), version: sanitize_version(::Regexp.last_match(2)),
ecosystem: 'golang' }
      when %r{^pkg:npm/([^@]+)@(.+)$}
        { name: sanitize_name(::Regexp.last_match(1)), version: sanitize_version(::Regexp.last_match(2)),
ecosystem: 'npm' }
      end
    end

    def sanitize_name(name)
      name.to_s.strip.gsub(%r{[^\w\-./@]}, '')
    end

    def sanitize_version(version)
      version.to_s.strip.gsub(/[^\w\-.+]/, '')
    end

    def validate_package!(pkg)
      raise ParseError, 'Package name cannot be empty' unless pkg[:name] && !pkg[:name].empty?

      raise ParseError, 'Package version cannot be empty' unless pkg[:version] && !pkg[:version].empty?

      raise ParseError, 'Package ecosystem cannot be empty' unless pkg[:ecosystem] && !pkg[:ecosystem].empty?

      raise ParseError, "Package name too long: #{pkg[:name].length} chars" if pkg[:name].length > 200

      raise ParseError, "Version string too long: #{pkg[:version].length} chars" if pkg[:version].length > 50
    end
  end
end
