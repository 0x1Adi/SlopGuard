module SlopGuard
  class HttpClient
    MAX_RETRIES = 3
    RATE_LIMIT = 10.0
    BURST_SIZE = 30

    def initialize(github_token: nil)
      @tokens = BURST_SIZE.to_f
      @last_refill = Time.now
      @mutex = Mutex.new
      @connections = {}
      @github_token = github_token || ENV['GITHUB_TOKEN']
      @github_rate_limit_hit = false
    end
    
    attr_reader :github_rate_limit_hit

    def get(url)
      acquire_token
      
      uri = URI(url)
      request = Net::HTTP::Get.new(uri)
      request['User-Agent'] = 'SlopGuard/1.0'
      
      # Add GitHub token if calling GitHub API
      if uri.hostname == 'api.github.com' && @github_token
        request['Authorization'] = "Bearer #{@github_token}"
      end
      
      attempt = 0
      max_attempts = MAX_RETRIES
      
      begin
        attempt += 1
        
        response = Net::HTTP.start(uri.hostname, uri.port,
                                    use_ssl: uri.scheme == 'https',
                                    read_timeout: 30,
                                    open_timeout: 10) do |http|
          http.request(request)
        end
        
        puts "[HTTP] #{response.code} #{url[0..70]}" if ENV['DEBUG']
        
        if response.is_a?(Net::HTTPSuccess)
          result = JSON.parse(response.body, symbolize_names: true)
          return result
        end
        
        if response.is_a?(Net::HTTPNotFound) || response.is_a?(Net::HTTPGone)
          return nil
        end
        
        # Handle GitHub rate limiting specifically
        if response.code == '403' && uri.hostname == 'api.github.com'
          rate_limit_remaining = response['X-RateLimit-Remaining'].to_i
          rate_limit_reset = response['X-RateLimit-Reset'].to_i
          
          if rate_limit_remaining == 0
            @github_rate_limit_hit = true
            reset_time = Time.at(rate_limit_reset)
            minutes_until_reset = ((reset_time - Time.now) / 60).ceil
            
            raise GitHubRateLimitError, "GitHub API rate limit exceeded. Resets in #{minutes_until_reset} minutes at #{reset_time}. #{@github_token ? 'Using authenticated requests (5000/hour limit)' : 'Add GITHUB_TOKEN environment variable for 5000/hour limit (currently 60/hour unauthenticated)'}"
          end
          
          # 403 but not rate limit (permission issue)
          puts "[WARN] GitHub API 403 (permission denied): #{url[0..60]}" if ENV['DEBUG']
          return nil
        end
        
        # Handle RubyGems rate limiting
        if response.code == '429'
          retry_after = response['Retry-After'].to_i
          if retry_after > 0 && retry_after < 300 && attempt < max_attempts
            sleep(retry_after)
            raise RateLimitError, "Rate limited, retrying after #{retry_after}s"
          end
          return nil
        end
        
        # Raise for 5xx errors
        if response.code.start_with?('5')
          raise "HTTP #{response.code}"
        end
        
        nil
        
      rescue JSON::ParserError
        nil
      rescue RateLimitError
        retry
      rescue GitHubRateLimitError
        raise  # Propagate to scanner
      rescue Net::ReadTimeout, Net::OpenTimeout, Errno::ECONNRESET, Errno::ECONNREFUSED
        if attempt < max_attempts
          sleep(0.5 * attempt)
          retry
        end
        nil
      rescue StandardError => e
        if e.message.include?('HTTP 5') && attempt < max_attempts
          sleep(0.5 * attempt)
          retry
        end
        nil
      end
    end

    def close_all
      # No connections to close
    end

    private
    
    class RateLimitError < StandardError; end
    class GitHubRateLimitError < StandardError; end

    def acquire_token
      loop do
        got_token = @mutex.synchronize do
          refill_tokens
          if @tokens >= 1.0
            @tokens -= 1.0
            true
          else
            false
          end
        end
        
        return if got_token
        sleep(0.02)
      end
    end

    def refill_tokens
      now = Time.now
      elapsed = now - @last_refill
      new_tokens = elapsed * RATE_LIMIT
      @tokens = [@tokens + new_tokens, BURST_SIZE.to_f].min
      @last_refill = now
    end
  end
end
