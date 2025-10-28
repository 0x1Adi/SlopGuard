require 'json'
require 'net/http'
require 'fileutils'
require 'concurrent'
require 'time'
require 'digest'

require_relative 'slopguard/parser'
require_relative 'slopguard/cache'
require_relative 'slopguard/http_client'
require_relative 'slopguard/ecosystem_adapter'
require_relative 'slopguard/adapter_factory'
require_relative 'slopguard/trust_scorer'
require_relative 'slopguard/anomaly_detector'
require_relative 'slopguard/scanner'
require_relative 'slopguard/gitlab_reporter'
require_relative 'slopguard/reporter'

module SlopGuard
  @http_client = nil
  @cache = nil
  
  def self.http_client
    @http_client ||= HttpClient.new
  end
  
  def self.cache
    @cache ||= Cache.new
  end
  
  def self.scan(sbom_path, options = {})
    Scanner.new(sbom_path, http: http_client, cache: cache).run
  end
end