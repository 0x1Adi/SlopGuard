# frozen_string_literal: true

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
      @api_call_count = 0
    end

    def get(url, headers = {})
      retry_count = 0

      begin
        acquire_token
        @api_call_count += 1

        uri = URI(url)
        request = Net::HTTP::Get.new(uri)
        headers.each { |k, v| request[k] = v }
        request['User-Agent'] = 'SlopGuard/1.0'

        response = Net::HTTP.start(uri.hostname, uri.port,
                                   use_ssl:      uri.scheme == 'https',
                                   read_timeout: TIMEOUT,
                                   open_timeout: TIMEOUT) do |http|
          http.request(request)
        end

        case response.code.to_i
        when 200
          JSON.parse(response.body, symbolize_names: true)
        when 404

          nil
        when 429

          retry_after = response['Retry-After']&.to_i || 60
          puts "[HTTP] Rate limited, waiting #{retry_after}s" if ENV['DEBUG']
          raise RateLimitError, retry_after
        when 500..599

          puts "[HTTP] Server error #{response.code}, retry #{retry_count}/#{MAX_RETRIES}" if ENV['DEBUG']
          raise ServerError, response.code
        else

          puts "[HTTP] Unexpected status #{response.code} for #{url}" if ENV['DEBUG']
          nil
        end
      rescue JSON::ParserError => e
        puts "[HTTP] JSON parse error: #{e.message}" if ENV['DEBUG']
        retry_count += 1
        if retry_count < MAX_RETRIES
          sleep(2**retry_count)
          retry
        end
        nil
      rescue Net::ReadTimeout, Net::OpenTimeout => e
        puts "[HTTP] Timeout: #{e.message}" if ENV['DEBUG']
        retry_count += 1
        if retry_count < MAX_RETRIES
          sleep(2**retry_count)
          retry
        end
        nil
      rescue RateLimitError => e
        retry_count += 1
        if retry_count < MAX_RETRIES
          sleep(e.retry_after)
          retry
        end
        nil
      rescue ServerError => e
        retry_count += 1
        if retry_count < MAX_RETRIES
          sleep(2**retry_count)
          retry
        end
        nil
      rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
        puts "[HTTP] Network error: #{e.message}" if ENV['DEBUG']
        nil
      rescue StandardError => e
        puts "[HTTP] Unexpected error: #{e.class} - #{e.message}" if ENV['DEBUG']
        nil
      end
    end

    private

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

    def acquire_token
      @mutex.synchronize do
        refill_tokens

        while @tokens <= 0
          sleep(1.0 / RATE_LIMIT)
          refill_tokens
        end

        @tokens -= 1
      end
    end

    def refill_tokens
      now = Time.now
      elapsed = now - @last_refill
      
      tokens_to_add = (elapsed * RATE_LIMIT).floor

      if tokens_to_add.positive?
        @tokens = [@tokens + tokens_to_add, BURST_SIZE].min
        @last_refill += (tokens_to_add.to_f / RATE_LIMIT)
      end
    end
  end
end
