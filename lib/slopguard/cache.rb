# frozen_string_literal: true

require 'digest'
require 'json'
require 'fileutils'

module SlopGuard
  class Cache
    CACHE_DIR = File.expand_path('~/.slopguard/cache')
    METADATA_TTL = 86_400
    TRUST_TTL = 604_800

    attr_reader :cache_hits, :cache_misses

    def initialize
      @lock = Mutex.new
      @cache_hits = 0
      @cache_misses = 0
      FileUtils.mkdir_p(CACHE_DIR, mode: 0o700)
    end

    def get(key, ttl: METADATA_TTL)
      path = cache_path(key)

      unless File.exist?(path)
        @cache_misses += 1
        return nil
      end

      begin
        data = JSON.parse(File.read(path), symbolize_names: true)

        if fresh?(data[:ts], ttl)
          @cache_hits += 1
          data[:val]
        else
          begin
            File.delete(path)
          rescue StandardError
            nil
          end
          @cache_misses += 1
          nil
        end
      rescue JSON::ParserError, Errno::ENOENT
        @cache_misses += 1
        nil
      end
    end

    def set(key, value, ttl: METADATA_TTL)
      path = cache_path(key)
      data = {
        val: value,
        ts:  Time.now.to_i,
        ttl: ttl,
      }

      FileUtils.mkdir_p(File.dirname(path))

      lock_path = "#{path}.lock"

      @lock.synchronize do
        File.open(lock_path, File::CREAT | File::EXCL) do |f|
          f.flock(File::LOCK_EX)

          temp_path = "#{path}.tmp"
          File.write(temp_path, JSON.generate(data))
          File.rename(temp_path, path)
        end
      rescue Errno::EEXIST
        sleep(0.01)
      ensure
        begin
          File.delete(lock_path)
        rescue StandardError
          nil
        end
      end
    end

    def fetch(key, ttl: METADATA_TTL)
      cached = get(key, ttl: ttl)
      return cached if cached

      result = yield
      set(key, result, ttl: ttl) if result
      result
    end

    def hit_rate
      total = @cache_hits + @cache_misses
      return 0.0 if total.zero?

      (@cache_hits.to_f / total * 100).round(1)
    end

    def clear
      FileUtils.rm_rf(CACHE_DIR)
      FileUtils.mkdir_p(CACHE_DIR, mode: 0o700)
      @cache_hits = 0
      @cache_misses = 0
    end

    def stats
      total_files = Dir.glob(File.join(CACHE_DIR, '**', '*.cache')).size
      expired = 0
      valid = 0

      Dir.glob(File.join(CACHE_DIR, '**', '*.cache')).each do |path|
        data = JSON.parse(File.read(path), symbolize_names: true)
        if fresh?(data[:ts], data[:ttl] || METADATA_TTL)
          valid += 1
        else
          expired += 1
        end
      rescue StandardError
        expired += 1
      end

      {
        total:    total_files,
        valid:    valid,
        expired:  expired,
        size_mb:  (dir_size(CACHE_DIR) / 1024.0 / 1024.0).round(2),
        hit_rate: hit_rate,
      }
    end

    private

    def fresh?(timestamp, ttl)
      Time.now.to_i - timestamp < ttl
    end

    def cache_path(key)
      hash = Digest::SHA256.hexdigest(key)
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
