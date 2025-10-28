require_relative 'adapters/rubygems_adapter'
require_relative 'adapters/pypi_adapter'

module SlopGuard
  class AdapterFactory
    def self.create(ecosystem, http_client, cache)
      case ecosystem.to_s.downcase
      when 'ruby', 'rubygems'
        Adapters::RubyGemsAdapter.new(http_client, cache)
      when 'python', 'pypi'
        Adapters::PyPIAdapter.new(http_client, cache)
      else
        raise ArgumentError, "Unsupported ecosystem: #{ecosystem}. Supported: ruby, python"
      end
    end

    def self.supported_ecosystems
      ['ruby', 'python']
    end
  end
end