require 'json'
require 'net/http'
require 'fileutils'
require 'concurrent'
require 'time'
require 'digest'

require_relative 'slopguard/parser'
require_relative 'slopguard/cache'
require_relative 'slopguard/http_client'
require_relative 'slopguard/trust_scorer'
require_relative 'slopguard/anomaly_detector'
require_relative 'slopguard/scanner'
require_relative 'slopguard/reporter'

module SlopGuard
  VERSION = '1.0.0'
  
  def self.scan(sbom_path, options = {})
    Scanner.new(sbom_path, options).run
  end
end