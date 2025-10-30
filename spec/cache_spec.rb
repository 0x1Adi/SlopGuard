require_relative '../lib/slopguard'
require 'fileutils'

RSpec.describe SlopGuard::Cache do
  let(:cache) { described_class.new }
  
  after(:each) do
    # Clean up cache directory after each test
    FileUtils.rm_rf(described_class::CACHE_DIR) if File.exist?(described_class::CACHE_DIR)
  end
  
  describe 'basic storage and retrieval' do
    it 'stores and retrieves values' do
      cache.set('test-key', { foo: 'bar' })
      result = cache.get('test-key')
      expect(result).to eq({ foo: 'bar' })
    end
    
    it 'returns nil for non-existent keys' do
      expect(cache.get('nonexistent')).to be_nil
    end
    
    it 'handles string values' do
      cache.set('string-key', 'plain string')
      expect(cache.get('string-key')).to eq('plain string')
    end
    
    it 'handles array values' do
      cache.set('array-key', [1, 2, 3])
      expect(cache.get('array-key')).to eq([1, 2, 3])
    end
  end
  
  describe 'TTL expiration' do
    it 'expires data after TTL' do
      cache.set('expire-key', 'value', ttl: 1)
      expect(cache.get('expire-key', ttl: 1)).to eq('value')
      
      sleep(2)
      expect(cache.get('expire-key', ttl: 1)).to be_nil
    end
    
    it 'respects different TTLs for different keys' do
      cache.set('short-ttl', 'value1', ttl: 1)
      cache.set('long-ttl', 'value2', ttl: 10)
      
      sleep(2)
      expect(cache.get('short-ttl', ttl: 1)).to be_nil
      expect(cache.get('long-ttl', ttl: 10)).to eq('value2')
    end
  end
  
  describe 'disk persistence' do
    it 'persists to disk' do
      cache.set('disk-key', 'disk-value')
      
      # Create new cache instance (simulates process restart)
      new_cache = described_class.new
      
      # Should retrieve from disk
      expect(new_cache.get('disk-key')).to eq('disk-value')
    end
    
    it 'handles complex data structures' do
      data = {
        name: 'rails',
        version: '7.0.0',
        downloads: 100_000_000,
        nested: {
          array: [1, 2, 3],
          hash: { key: 'value' }
        }
      }
      
      cache.set('complex-key', data)
      new_cache = described_class.new
      
      expect(new_cache.get('complex-key')).to eq(data)
    end
  end
  
  describe 'fetch pattern' do
    it 'returns cached value if present' do
      cache.set('fetch-key', 'cached-value')
      
      result = cache.fetch('fetch-key') do
        'block-value'  # Should not execute
      end
      
      expect(result).to eq('cached-value')
    end
    
    it 'executes block and caches result if not present' do
      call_count = 0
      
      result = cache.fetch('new-key') do
        call_count += 1
        'computed-value'
      end
      
      expect(result).to eq('computed-value')
      expect(call_count).to eq(1)
      
      # Second call should use cache
      result2 = cache.fetch('new-key') do
        call_count += 1
        'should-not-execute'
      end
      
      expect(result2).to eq('computed-value')
      expect(call_count).to eq(1)  # Block not called again
    end
    
    it 'respects TTL in fetch' do
      result = cache.fetch('ttl-key', ttl: 1) do
        'value'
      end
      
      expect(result).to eq('value')
      
      sleep(2)
      
      # Should re-execute block after expiration
      result2 = cache.fetch('ttl-key', ttl: 1) do
        'new-value'
      end
      
      expect(result2).to eq('new-value')
    end
  end
  
  describe 'thread safety' do
    it 'handles concurrent writes' do
      threads = 10.times.map do |i|
        Thread.new do
          cache.set("thread-key-#{i}", "value-#{i}")
        end
      end
      
      threads.each(&:join)
      
      10.times do |i|
        expect(cache.get("thread-key-#{i}")).to eq("value-#{i}")
      end
    end
    
    it 'handles concurrent reads' do
      cache.set('shared-key', 'shared-value')
      
      results = 10.times.map do
        Thread.new { cache.get('shared-key') }
      end.map(&:value)
      
      expect(results).to all(eq('shared-value'))
    end
    
    # REMOVED: Memory pruning test (no longer applicable with disk-only cache)
  end
  
  describe 'key collision handling' do
    it 'stores different keys separately' do
      cache.set('key1', 'value1')
      cache.set('key2', 'value2')
      
      expect(cache.get('key1')).to eq('value1')
      expect(cache.get('key2')).to eq('value2')
    end
    
    it 'overwrites existing keys' do
      cache.set('overwrite', 'original')
      cache.set('overwrite', 'updated')
      
      expect(cache.get('overwrite')).to eq('updated')
    end
  end
  
  describe 'stats' do
    it 'returns cache statistics' do
      cache.set('key1', 'value1')
      cache.set('key2', 'value2')
      
      stats = cache.stats
      
      expect(stats[:total]).to be >= 2
      expect(stats[:valid]).to be >= 2
      expect(stats[:expired]).to be >= 0.0
      expect(stats[:size_mb]).to be >= 0.0
    end
  end
  
  describe 'clear' do
    it 'removes all cached data' do
      cache.set('key1', 'value1')
      cache.set('key2', 'value2')
      
      expect(cache.get('key1')).to eq('value1')
      
      cache.clear
      
      expect(cache.get('key1')).to be_nil
      expect(cache.get('key2')).to be_nil
    end
  end
end
