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
      return nil unless purl =~ %r{^pkg:gem/([^@]+)@(.+)$}
      { name: $1, version: $2, ecosystem: 'ruby' }
    end
  end
end