require 'digest'
require 'json'
require 'fileutils'

module SlopGuard
  class Cache
    CACHE_DIR = File.expand_path('~/.slopguard/cache')
    METADATA_TTL = 86400      # 24 hours
    TRUST_TTL = 604800        # 7 days
    
    def initialize
      @lock = Mutex.new
      FileUtils.mkdir_p(CACHE_DIR, mode: 0700)
    end
    
    # Get cached value if it exists and is fresh
    # Returns nil if not found or expired
    def get(key, ttl: METADATA_TTL)
      path = cache_path(key)
      
      return nil unless File.exist?(path)
      
      begin
        data = JSON.parse(File.read(path), symbolize_names: true)
        
        # Check if expired
        if fresh?(data[:ts], ttl)
          data[:val]
        else
          # Delete expired entry
          File.delete(path) rescue nil
          nil
        end
      rescue JSON::ParserError, Errno::ENOENT
        # Corrupted or deleted file - return nil
        nil
      end
    end
    
    # Set cached value with timestamp
    # Thread-safe: uses file locking to prevent race conditions
    def set(key, value, ttl: METADATA_TTL)
      path = cache_path(key)
      data = {
        val: value,
        ts: Time.now.to_i,
        ttl: ttl
      }
      
      # Create directory if needed
      FileUtils.mkdir_p(File.dirname(path))
      
      # Write atomically to prevent partial reads
      # Use lock file to prevent cache stampedes
      lock_path = "#{path}.lock"
      
      @lock.synchronize do
        File.open(lock_path, File::CREAT | File::EXCL) do |f|
          f.flock(File::LOCK_EX)
          
          # Write to temp file then rename (atomic operation)
          temp_path = "#{path}.tmp"
          File.write(temp_path, JSON.generate(data))
          File.rename(temp_path, path)
        end
      rescue Errno::EEXIST
        # Another thread is writing - wait briefly then skip
        sleep(0.01)
      ensure
        File.delete(lock_path) rescue nil
      end
    end
    
    # Check and set pattern to prevent cache stampedes
    # If key exists and is fresh, return cached value
    # Otherwise, execute block and cache result
    def fetch(key, ttl: METADATA_TTL)
      cached = get(key, ttl: ttl)
      return cached if cached
      
      # Not cached - execute block
      result = yield
      set(key, result, ttl: ttl) if result
      result
    end
    
    # Clear entire cache (useful for testing)
    def clear
      FileUtils.rm_rf(CACHE_DIR)
      FileUtils.mkdir_p(CACHE_DIR, mode: 0700)
    end
    
    # Get cache statistics for monitoring
    def stats
      total_files = Dir.glob(File.join(CACHE_DIR, '**', '*.cache')).size
      expired = 0
      valid = 0
      
      Dir.glob(File.join(CACHE_DIR, '**', '*.cache')).each do |path|
        begin
          data = JSON.parse(File.read(path), symbolize_names: true)
          if fresh?(data[:ts], data[:ttl] || METADATA_TTL)
            valid += 1
          else
            expired += 1
          end
        rescue
          expired += 1
        end
      end
      
      {
        total: total_files,
        valid: valid,
        expired: expired,
        size_mb: (dir_size(CACHE_DIR) / 1024.0 / 1024.0).round(2)
      }
    end
    
    private
    
    def fresh?(timestamp, ttl)
      Time.now.to_i - timestamp < ttl
    end
    
    def cache_path(key)
      # Use SHA256 for deterministic, collision-resistant hashing
      hash = Digest::SHA256.hexdigest(key)
      # Split into subdirectories to avoid too many files in one dir
      # Format: ~/.slopguard/cache/ab/cd/abcd1234...cache
      File.join(CACHE_DIR, hash[0..1], hash[2..3], "#{hash}.cache")
    end
    
    def dir_size(dir)
      size = 0
      Dir.glob(File.join(dir, '**', '*')).each do |file|
        size += File.size(file) if File.file?(file)
      end
      size
    end
  end
end
