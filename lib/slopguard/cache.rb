module SlopGuard
  class Cache
    CACHE_DIR = File.expand_path('~/.slopguard/cache')
    METADATA_TTL = 86400
    TRUST_TTL = 604800

    def initialize
      @memory = {}
      FileUtils.mkdir_p(CACHE_DIR)
    end

    def get(key, ttl: METADATA_TTL)
      if @memory[key] && fresh?(@memory[key][:ts], ttl)
        return @memory[key][:val]
      end

      disk_path = key_path(key)
      if File.exist?(disk_path)
        data = JSON.parse(File.read(disk_path), symbolize_names: true)
        if fresh?(data[:ts], ttl)
          @memory[key] = data
          return data[:val]
        end
      end
      nil
    end

    def set(key, value, ttl: METADATA_TTL)
      data = { val: value, ts: Time.now.to_i, ttl: ttl }
      @memory[key] = data
      
      path = key_path(key)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, JSON.generate(data))
    end

    private

    def fresh?(timestamp, ttl)
      Time.now.to_i - timestamp < ttl
    end

    def key_path(key)
      hash = Digest::SHA256.hexdigest(key)
      File.join(CACHE_DIR, hash[0..1], hash[2..3], hash)
    end
  end
end
