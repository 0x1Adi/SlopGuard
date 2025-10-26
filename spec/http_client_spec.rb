require_relative '../lib/slopguard'
require 'webmock/rspec'

RSpec.describe SlopGuard::HttpClient do
  let(:client) { described_class.new }
  
  describe 'rate limiting' do
    it 'allows burst of requests up to BURST_SIZE' do
      stub_request(:get, /rubygems\.org/).to_return(status: 200, body: '{"name":"test"}')
      
      # Should handle burst without delays
      start_time = Time.now
      described_class::BURST_SIZE.times do
        client.get('https://rubygems.org/api/v1/gems/test.json')
      end
      elapsed = Time.now - start_time
      
      # Should complete quickly (under 1 second for burst)
      expect(elapsed).to be < 1.0
    end
    
    it 'enforces rate limit after burst depleted' do
      stub_request(:get, /rubygems\.org/).to_return(status: 200, body: '{"name":"test"}')
      
      # Deplete burst
      described_class::BURST_SIZE.times do
        client.get('https://rubygems.org/api/v1/gems/test.json')
      end
      
      # Next requests should be rate limited
      start_time = Time.now
      5.times do
        client.get('https://rubygems.org/api/v1/gems/test.json')
      end
      elapsed = Time.now - start_time
      
      # Should take at least 0.5 seconds (5 requests / 10 req/s)
      expect(elapsed).to be >= 0.4
    end
  end
  
  describe 'response handling' do
    it 'parses successful JSON responses' do
      stub_request(:get, 'https://rubygems.org/api/v1/gems/rails.json')
        .to_return(status: 200, body: '{"name":"rails","downloads":300000000}')
      
      result = client.get('https://rubygems.org/api/v1/gems/rails.json')
      expect(result[:name]).to eq('rails')
      expect(result[:downloads]).to eq(300000000)
    end
    
    it 'returns nil for 404 responses' do
      stub_request(:get, 'https://rubygems.org/api/v1/gems/nonexistent.json')
        .to_return(status: 404)
      
      result = client.get('https://rubygems.org/api/v1/gems/nonexistent.json')
      expect(result).to be_nil
    end
    
    it 'returns nil for 410 Gone responses' do
      stub_request(:get, 'https://rubygems.org/api/v1/gems/deleted.json')
        .to_return(status: 410)
      
      result = client.get('https://rubygems.org/api/v1/gems/deleted.json')
      expect(result).to be_nil
    end
  end
  
  describe 'GitHub rate limit handling' do
    it 'raises GitHubRateLimitError when rate limited' do
      reset_time = Time.now.to_i + 3600
      
      stub_request(:get, 'https://api.github.com/repos/rails/rails')
        .to_return(
          status: 403,
          headers: {
            'X-RateLimit-Remaining' => '0',
            'X-RateLimit-Reset' => reset_time.to_s
          }
        )
      
      expect {
        client.get('https://api.github.com/repos/rails/rails')
      }.to raise_error(SlopGuard::HttpClient::GitHubRateLimitError, /rate limit exceeded/)
    end
    
    it 'sets github_rate_limit_hit flag when rate limited' do
      reset_time = Time.now.to_i + 3600
      
      stub_request(:get, 'https://api.github.com/repos/rails/rails')
        .to_return(
          status: 403,
          headers: {
            'X-RateLimit-Remaining' => '0',
            'X-RateLimit-Reset' => reset_time.to_s
          }
        )
      
      expect(client.github_rate_limit_hit).to be false
      
      begin
        client.get('https://api.github.com/repos/rails/rails')
      rescue SlopGuard::HttpClient::GitHubRateLimitError
      end
      
      expect(client.github_rate_limit_hit).to be true
    end
    
    it 'adds GitHub token to requests when provided' do
      client_with_token = described_class.new(github_token: 'test-token-123')
      
      stub = stub_request(:get, 'https://api.github.com/repos/rails/rails')
        .with(headers: { 'Authorization' => 'Bearer test-token-123' })
        .to_return(status: 200, body: '{"name":"rails"}')
      
      client_with_token.get('https://api.github.com/repos/rails/rails')
      expect(stub).to have_been_requested
    end
  end
  
  describe 'retry logic' do
    it 'retries on timeout errors' do
      call_count = 0
      
      stub_request(:get, 'https://rubygems.org/api/v1/gems/test.json')
        .to_return do
          call_count += 1
          if call_count < 3
            raise Net::ReadTimeout
          else
            { status: 200, body: '{"name":"test"}' }
          end
        end
      
      result = client.get('https://rubygems.org/api/v1/gems/test.json')
      expect(result[:name]).to eq('test')
      expect(call_count).to eq(3)
    end
    
    it 'gives up after MAX_RETRIES attempts' do
      stub_request(:get, 'https://rubygems.org/api/v1/gems/always-timeout.json')
        .to_timeout
      
      result = client.get('https://rubygems.org/api/v1/gems/always-timeout.json')
      expect(result).to be_nil
    end
    
    it 'retries on 5xx server errors' do
      call_count = 0
      
      stub_request(:get, 'https://rubygems.org/api/v1/gems/test.json')
        .to_return do
          call_count += 1
          if call_count < 2
            { status: 503 }
          else
            { status: 200, body: '{"name":"test"}' }
          end
        end
      
      result = client.get('https://rubygems.org/api/v1/gems/test.json')
      expect(result[:name]).to eq('test')
    end
  end
  
  describe '429 rate limit handling' do
    it 'respects Retry-After header' do
      stub_request(:get, 'https://rubygems.org/api/v1/gems/test.json')
        .to_return(
          { status: 429, headers: { 'Retry-After' => '2' } },
          { status: 200, body: '{"name":"test"}' }
        )
      
      start_time = Time.now
      result = client.get('https://rubygems.org/api/v1/gems/test.json')
      elapsed = Time.now - start_time
      
      expect(result[:name]).to eq('test')
      expect(elapsed).to be >= 2.0
    end
    
    it 'returns nil if Retry-After is too long' do
      stub_request(:get, 'https://rubygems.org/api/v1/gems/test.json')
        .to_return(status: 429, headers: { 'Retry-After' => '500' })
      
      result = client.get('https://rubygems.org/api/v1/gems/test.json')
      expect(result).to be_nil
    end
  end
end
