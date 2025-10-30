require_relative 'adapters/rubygems_adapter'
require_relative 'adapters/pypi_adapter'
require_relative 'adapters/golang_adapter'

module SlopGuard
  class AdapterFactory
    SUPPORTED_ECOSYSTEMS = ['ruby', 'rubygems', 'python', 'pypi', 'golang', 'go'].freeze
    
    def self.create(ecosystem, http_client, cache)
      normalized = normalize_ecosystem(ecosystem)
      
      case normalized
      when 'ruby'
        Adapters::RubyGemsAdapter.new(http_client, cache)
      when 'python'
        Adapters::PyPIAdapter.new(http_client, cache)
      when 'golang'
        Adapters::GolangAdapter.new(http_client, cache)
      else
        raise ArgumentError, "Unsupported ecosystem: #{ecosystem}. Supported: #{supported_ecosystems.join(', ')}"
      end
    end
    
    # NEW: Check if ecosystem is supported before attempting to create adapter
    def self.supported?(ecosystem)
      return false if ecosystem.nil? || ecosystem.to_s.empty?
      
      normalized = normalize_ecosystem(ecosystem)
      ['ruby', 'python', 'golang'].include?(normalized)
    end
    
    def self.supported_ecosystems
      ['ruby', 'python', 'golang']
    end
    
    private
    
    def self.normalize_ecosystem(ecosystem)
      case ecosystem.to_s.downcase
      when 'ruby', 'rubygems', 'gem'
        'ruby'
      when 'python', 'pypi'
        'python'
      when 'golang', 'go'
        'golang'
      else
        ecosystem.to_s.downcase
      end
    end
  end
end
