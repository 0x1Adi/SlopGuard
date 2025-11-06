# frozen_string_literal: true

require 'active_support/cache'
require 'active_support/notifications'
require 'fileutils'

module SlopGuard
  class Cache
    CACHE_DIR = File.expand_path('~/.slopguard/cache')
    METADATA_TTL = 86_400      # 1 day
    TRUST_TTL = 604_800        # 7 days
    MAX_CACHE_SIZE = 100       # 100 MB

    attr_reader :cache_hits, :cache_misses

    def initialize
      FileUtils.mkdir_p(CACHE_DIR)

      @store = ActiveSupport::Cache::FileStore.new(
        CACHE_DIR,
        expires_in:         TRUST_TTL, # Default expiration
        max_size:           MAX_CACHE_SIZE * 1024 * 1024, # Auto-cleanup when exceeds
        race_condition_ttl: 10 # Prevents stampeding herd
      )

      @cache_hits = 0
      @cache_misses = 0
    end

    def get(key, ttl: METADATA_TTL)
      value = @store.read(key)

      if value
        @cache_hits += 1
        value
      else
        @cache_misses += 1
        nil
      end
    end

    def set(key, value, ttl: METADATA_TTL)
      @store.write(key, value, expires_in: ttl)
    end

    def fetch(key, ttl: METADATA_TTL)
      value = @store.read(key)

      if value
        @cache_hits += 1
        value
      else
        @cache_misses += 1
        result = yield
        @store.write(key, result, expires_in: ttl) if result
        result
      end
    end

    def clear
      @store.clear
      @cache_hits = 0
      @cache_misses = 0
    end

    def hit_rate
      total = @cache_hits + @cache_misses
      return 0.0 if total.zero?

      (@cache_hits.to_f / total * 100).round(1)
    end

    def stats
      files = Dir.glob(File.join(CACHE_DIR, '**', '*')).select { |f| File.file?(f) }
      size = files.sum { |f| File.size(f) }

      {
        total:    files.size,
        size_mb:  (size / 1024.0 / 1024.0).round(2),
        hit_rate: hit_rate,
      }
    end
  end
end
