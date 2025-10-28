require 'digest'
require 'json'
require 'fileutils'

module SlopGuard
  class Cache
    CACHE_DIR = File.expand_path('~/.slopguard/cache')
    METADATA_TTL = 86400
    TRUST_TTL = 604800
    MAX_MEMORY_ENTRIES = 1000
    
    def initialize
      @memory = {}
      @mutex = Mutex.new
      FileUtils.mkdir_p(CACHE_DIR, mode: 0700)
    end
    
    def get(key, ttl: METADATA_TTL)
      @mutex.synchronize do
        # Check memory first
        if @memory[key] && fresh?(@memory[key][:ts], ttl)
          return @memory[key][:val]
        end
        
        # Check disk
        disk_path = key_path(key)
        if File.exist?(disk_path)
          data = JSON.parse(File.read(disk_path), symbolize_names: true)
          if fresh?(data[:ts], ttl)
            # Load into memory
            prune_memory if @memory.size >= MAX_MEMORY_ENTRIES
            @memory[key] = data
            return data[:val]
          else
            # Expired - delete it
            File.delete(disk_path) rescue nil
          end
        end
        
        nil
      end
    end
    
    def set(key, value, ttl: METADATA_TTL)
      data = { val: value, ts: Time.now.to_i, ttl: ttl }
      
      @mutex.synchronize do
        # Store in memory
        prune_memory if @memory.size >= MAX_MEMORY_ENTRIES
        @memory[key] = data
        
        # Write to disk
        path = key_path(key)
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, JSON.generate(data))
      end
    end
    
    private
    
    def fresh?(timestamp, ttl)
      Time.now.to_i - timestamp < ttl
    end
    
    def key_path(key)
      # Use SHA256 for deterministic hashing (same key = same path across processes)
      hash = Digest::SHA256.hexdigest(key)
      # First 2 chars = first level dir, next 2 = second level dir
      File.join(CACHE_DIR, hash[0..1], hash[2..3], "#{hash}.cache")
    end
    
    def prune_memory
      # Remove oldest 10% of entries
      to_remove = (@memory.size * 0.1).to_i
      @memory.keys.first(to_remove).each { |k| @memory.delete(k) }
    end
  end
end
