require 'json'

module SlopGuard
  class Parser
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit
    MAX_COMPONENTS = 10_000  # Sanity limit
    
    class ParseError < StandardError; end
    
    def initialize(sbom_path)
      @sbom_path = sbom_path
    end

    def parse
      # FIXED: Input validation before processing
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

      # FIXED: Validate SBOM structure
      validate_sbom_structure!(data)

      components = data[:components] || []
      
      # FIXED: Check component count
      if components.size > MAX_COMPONENTS
        raise ParseError, "SBOM contains too many components (#{components.size}), max is #{MAX_COMPONENTS}"
      end

      packages = []
      components.each_with_index do |component, idx|
        begin
          pkg = parse_component(component)
          packages << pkg if pkg
        rescue => e
          # Log error but continue processing other components
          $stderr.puts "[WARN] Skipping component #{idx}: #{e.message}" if ENV['DEBUG']
        end
      end

      packages.uniq { |p| "#{p[:ecosystem]}:#{p[:name]}:#{p[:version]}" }
    end

    private

    def validate_file!
      # Check file exists
      unless File.exist?(@sbom_path)
        raise ParseError, "SBOM file does not exist: #{@sbom_path}"
      end

      # Check file is readable
      unless File.readable?(@sbom_path)
        raise ParseError, "SBOM file is not readable: #{@sbom_path}"
      end

      # Check file size
      file_size = File.size(@sbom_path)
      if file_size > MAX_FILE_SIZE
        raise ParseError, "SBOM file too large: #{file_size} bytes (max #{MAX_FILE_SIZE})"
      end

      if file_size == 0
        raise ParseError, "SBOM file is empty"
      end
    end

    def validate_sbom_structure!(data)
      unless data.is_a?(Hash)
        raise ParseError, "SBOM root must be an object, got #{data.class}"
      end

      # Check for CycloneDX format
      unless data[:bomFormat] == 'CycloneDX'
        raise ParseError, "Unsupported BOM format: #{data[:bomFormat]}"
      end

      # Check version
      unless data[:specVersion]
        raise ParseError, "Missing specVersion in SBOM"
      end

      # Components should be an array
      if data[:components] && !data[:components].is_a?(Array)
        raise ParseError, "Components must be an array, got #{data[:components].class}"
      end
    end

    def parse_component(component)
      # FIXED: Validate component structure
      unless component.is_a?(Hash)
        raise ParseError, "Component must be an object, got #{component.class}"
      end

      purl = component[:purl]
      return nil unless purl

      # FIXED: Validate PURL format
      unless purl.is_a?(String) && purl.start_with?('pkg:')
        raise ParseError, "Invalid PURL format: #{purl}"
      end

      pkg = parse_purl(purl)
      return nil unless pkg

      # FIXED: Validate parsed package
      validate_package!(pkg)
      
      pkg
    end

    def parse_purl(purl)
      case purl
      when %r{^pkg:gem/([^@]+)@(.+)$}
        { name: sanitize_name($1), version: sanitize_version($2), ecosystem: 'ruby' }
      when %r{^pkg:pypi/([^@]+)@(.+)$}
        { name: sanitize_name($1), version: sanitize_version($2), ecosystem: 'python' }
      when %r{^pkg:golang/([^@]+)@(.+)$}
        { name: sanitize_name($1), version: sanitize_version($2), ecosystem: 'golang' }
      when %r{^pkg:npm/([^@]+)@(.+)$}
        { name: sanitize_name($1), version: sanitize_version($2), ecosystem: 'npm' }
      else
        # Unsupported ecosystem - skip silently
        nil
      end
    end

    def sanitize_name(name)
      # FIXED: Basic sanitization to prevent injection
      name.to_s.strip.gsub(/[^\w\-\.\/\@]/, '')
    end

    def sanitize_version(version)
      # FIXED: Basic version sanitization
      version.to_s.strip.gsub(/[^\w\-\.\+]/, '')
    end

    def validate_package!(pkg)
      # Check required fields
      unless pkg[:name] && !pkg[:name].empty?
        raise ParseError, "Package name cannot be empty"
      end

      unless pkg[:version] && !pkg[:version].empty?
        raise ParseError, "Package version cannot be empty"
      end

      unless pkg[:ecosystem] && !pkg[:ecosystem].empty?
        raise ParseError, "Package ecosystem cannot be empty"
      end

      # Sanity check lengths
      if pkg[:name].length > 200
        raise ParseError, "Package name too long: #{pkg[:name].length} chars"
      end

      if pkg[:version].length > 50
        raise ParseError, "Version string too long: #{pkg[:version].length} chars"
      end
    end
  end
end
