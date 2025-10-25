module SlopGuard
  class HttpClient
    MAX_RETRIES = 3
    RATE_LIMIT = 10.0

    def initialize
      @tokens = 20.0
      @last_refill = Time.now
      @mutex = Mutex.new
    end

    def get(url)
      acquire_token
      
      uri = URI(url)
      request = Net::HTTP::Get.new(uri)
      request['User-Agent'] = 'SlopGuard/1.0'
      
      retries = 0
      begin
        response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true, read_timeout: 30) do |http|
          http.request(request)
        end
        
        if response.is_a?(Net::HTTPSuccess)
          return JSON.parse(response.body, symbolize_names: true)
        end
        return nil if response.is_a?(Net::HTTPNotFound)
        
        raise "HTTP #{response.code}"
      rescue JSON::ParserError
        nil
      rescue => e
        retries += 1
        if retries < MAX_RETRIES
          sleep(2 ** retries)
          retry
        end
        nil
      end
    end

    private

    def acquire_token
      @mutex.synchronize do
        refill_tokens
        while @tokens < 1
          sleep(0.1)
          refill_tokens
        end
        @tokens -= 1
      end
    end

    def refill_tokens
      now = Time.now
      elapsed = now - @last_refill
      new_tokens = elapsed * RATE_LIMIT
      @tokens = [@tokens + new_tokens, 20.0].min
      @last_refill = now
    end
  end
end
