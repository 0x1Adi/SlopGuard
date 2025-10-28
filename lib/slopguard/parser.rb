module SlopGuard
  class Parser
    def initialize(sbom_path)
      @sbom_path = sbom_path
    end

    def parse
      data = JSON.parse(File.read(@sbom_path))
      components = data['components'] || []
      
      components.filter_map do |comp|
        next unless comp['purl']
        parse_purl(comp['purl'])
      end
    end

    private

    def parse_purl(purl)
      case purl
      when %r{^pkg:gem/([^@]+)@(.+)$}
        { name: $1, version: $2, ecosystem: 'ruby' }
      when %r{^pkg:pypi/([^@]+)@(.+)$}
        { name: $1, version: $2, ecosystem: 'python' }
      when %r{^pkg:npm/([^@]+)@(.+)$}
        # npm support placeholder - will skip until adapter implemented
        nil
      when %r{^pkg:cargo/([^@]+)@(.+)$}
        # cargo support placeholder - will skip until adapter implemented
        nil
      else
        # Unsupported ecosystem - skip silently
        nil
      end
    end
  end
end