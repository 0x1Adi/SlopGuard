require 'net/http'
require 'json'
require 'uri'

module SlopGuard
  class HttpClient
    RATE_LIMIT = 10
    BURST_SIZE = 20
    TIMEOUT = 30
    MAX_RETRIES = 3

    attr_reader :api_call_count

    def initialize
      @tokens = BURST_SIZE
      @last_refill = Time.now
      @mutex = Mutex.new
      @api_call_count = 0  # NEW: Track API calls
    end

    # Generic GET request with retry logic and rate limiting
    # Returns parsed JSON hash with symbolized keys, or nil on error/404
    def get(url, headers = {})
      retry_count = 0
      
      begin
        acquire_token
        @api_call_count += 1  # NEW: Increment counter
        
        uri = URI(url)
        request = Net::HTTP::Get.new(uri)
        headers.each { |k, v| request[k] = v }
        request['User-Agent'] = 'SlopGuard/1.0'
        
        response = Net::HTTP.start(uri.hostname, uri.port, 
                                   use_ssl: uri.scheme == 'https', 
                                   read_timeout: TIMEOUT,
                                   open_timeout: TIMEOUT) do |http|
          http.request(request)
        end
        
        case response.code.to_i
        when 200
          JSON.parse(response.body, symbolize_names: true)
        when 404
          # Package doesn't exist - return nil
          nil
        when 429
          # Rate limited - respect Retry-After header
          retry_after = response['Retry-After']&.to_i || 60
          puts "[HTTP] Rate limited, waiting #{retry_after}s" if ENV['DEBUG']
          raise RateLimitError.new(retry_after)
        when 500..599
          # Server error - retry with exponential backoff
          puts "[HTTP] Server error #{response.code}, retry #{retry_count}/#{MAX_RETRIES}" if ENV['DEBUG']
          raise ServerError.new(response.code)
        else
          # Other errors - don't retry
          puts "[HTTP] Unexpected status #{response.code} for #{url}" if ENV['DEBUG']
          nil
        end
      rescue JSON::ParserError => e
        # Invalid JSON response
        puts "[HTTP] JSON parse error: #{e.message}" if ENV['DEBUG']
        retry_count += 1
        if retry_count < MAX_RETRIES
          sleep(2 ** retry_count)
          retry
        end
        nil
      rescue Net::ReadTimeout, Net::OpenTimeout => e
        # Network timeout
        puts "[HTTP] Timeout: #{e.message}" if ENV['DEBUG']
        retry_count += 1
        if retry_count < MAX_RETRIES
          sleep(2 ** retry_count)
          retry
        end
        nil
      rescue RateLimitError => e
        # Rate limit - wait and retry
        retry_count += 1
        if retry_count < MAX_RETRIES
          sleep(e.retry_after)
          retry
        end
        nil
      rescue ServerError => e
        # Server error - exponential backoff
        retry_count += 1
        if retry_count < MAX_RETRIES
          sleep(2 ** retry_count)
          retry
        end
        nil
      rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
        # Network errors - typically not worth retrying
        puts "[HTTP] Network error: #{e.message}" if ENV['DEBUG']
        nil
      rescue StandardError => e
        # Unexpected errors
        puts "[HTTP] Unexpected error: #{e.class} - #{e.message}" if ENV['DEBUG']
        nil
      end
    end

    private

    # Custom exceptions for retry logic
    class RateLimitError < StandardError
      attr_reader :retry_after
      def initialize(retry_after)
        @retry_after = retry_after
        super("Rate limited, retry after #{retry_after}s")
      end
    end

    class ServerError < StandardError
      attr_reader :status_code
      def initialize(status_code)
        @status_code = status_code
        super("Server error: #{status_code}")
      end
    end

    # Token bucket rate limiting
    # Ensures we don't exceed RATE_LIMIT requests per second
    def acquire_token
      @mutex.synchronize do
        refill_tokens
        
        # Wait if no tokens available
        while @tokens <= 0
          sleep(1.0 / RATE_LIMIT)
          refill_tokens
        end
        
        @tokens -= 1
      end
    end

    # Refill tokens based on elapsed time
    def refill_tokens
      now = Time.now
      elapsed = now - @last_refill
      new_tokens = (elapsed * RATE_LIMIT).floor
      
      if new_tokens > 0
        @tokens = [@tokens + new_tokens, BURST_SIZE].min
        @last_refill = now
      end
    end
  end
end
