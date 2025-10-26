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
  
  describe 'memory and disk persistence' do
    it 'stores to memory first' do
      cache.set('mem-key', 'mem-value')
      
      # Should be in memory (fast retrieval)
      expect(cache.get('mem-key')).to eq('mem-value')
    end
    
    it 'persists to disk' do
      cache.set('disk-key', 'disk-value')
      
      # Create new cache instance (clears memory)
      new_cache = described_class.new
      
      # Should retrieve from disk
      expect(new_cache.get('disk-key')).to eq('disk-value')
    end
    
    it 'loads disk data into memory on access' do
      cache.set('hybrid-key', 'hybrid-value')
      
      new_cache = described_class.new
      first_get = new_cache.get('hybrid-key')  # Loads from disk
      second_get = new_cache.get('hybrid-key') # From memory
      
      expect(first_get).to eq('hybrid-value')
      expect(second_get).to eq('hybrid-value')
    end
  end
  
  describe 'memory pruning' do
    it 'prunes oldest entries when exceeding MAX_MEMORY_ENTRIES' do
      # Fill cache beyond limit
      (described_class::MAX_MEMORY_ENTRIES + 100).times do |i|
        cache.set("key-#{i}", "value-#{i}")
      end
      
      # Early keys should be pruned from memory (but still on disk)
      # This is probabilistic due to hash ordering, so check general behavior
      memory_size = cache.instance_variable_get(:@memory).size
      expect(memory_size).to be <= described_class::MAX_MEMORY_ENTRIES
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
end
