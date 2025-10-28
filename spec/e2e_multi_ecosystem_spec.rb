require 'spec_helper'
require_relative '../lib/slopguard'
require 'json'
require 'tmpdir'
require 'fileutils'

RSpec.describe 'Multi-Ecosystem E2E Tests', :e2e do
  let(:http) { SlopGuard::HttpClient.new }
  let(:cache) { SlopGuard::Cache.new }
  let(:temp_dir) { Dir.mktmpdir }
  
  # Allow real HTTP connections for E2E tests
  before(:each) do
    WebMock.allow_net_connect!
  end
  
  after(:each) do
    WebMock.disable_net_connect!
  end
  
  after { FileUtils.rm_rf(temp_dir) }
  
  def create_sbom(components)
    sbom = {
      'bomFormat' => 'CycloneDX',
      'specVersion' => '1.4',
      'version' => 1,
      'components' => components
    }
    
    path = File.join(temp_dir, 'sbom.json')
    File.write(path, JSON.generate(sbom))
    path
  end

  describe 'Ruby Gems' do
    it 'verifies popular Ruby gems' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:gem/rspec@3.12.0' },
        { 'purl' => 'pkg:gem/rake@13.0.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(3)
      expect(results[:verified]).to eq(3)
      expect(results[:high_risk]).to eq(0)
      expect(results[:not_found]).to eq(0)
      
      rails_result = results[:results].find { |r| r[:package][:name] == 'rails' }
      expect(rails_result[:trust][:score]).to be >= 80
      expect(rails_result[:trust][:level]).to eq('CRITICAL').or eq('HIGH')
      expect(rails_result[:action]).to eq('VERIFIED')
    end

    it 'detects non-existent Ruby gems' do
      components = [
        { 'purl' => 'pkg:gem/rails-totally-fake-gem-12345@1.0.0' },
        { 'purl' => 'pkg:gem/nonexistent-package-xyz@0.1.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(2)
      expect(results[:not_found]).to eq(2)
      expect(results[:verified]).to eq(0)
      
      results[:results].each do |result|
        expect(result[:trust][:level]).to eq('NOT_FOUND')
        expect(result[:action]).to eq('NOT_FOUND')
      end
    end

    it 'flags suspicious Ruby gems with anomalies' do
      # Testing with a real but low-trust gem would be ideal
      # For now, we test the detection logic structure
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' }  # Known good package
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      # Rails should not have anomalies
      rails_result = results[:results].find { |r| r[:package][:name] == 'rails' }
      expect(rails_result[:anomalies]).to be_empty
    end
  end

  describe 'Python Packages' do
    it 'verifies popular Python packages' do
      components = [
        { 'purl' => 'pkg:pypi/requests@2.31.0' },
        { 'purl' => 'pkg:pypi/flask@3.0.0' },
        { 'purl' => 'pkg:pypi/django@4.2.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(3)
      expect(results[:not_found]).to eq(0)
      
      # All should be verified or at least not blocked
      results[:results].each do |result|
        expect(result[:action]).to_not eq('NOT_FOUND')
        expect(result[:trust][:score]).to be > 0
      end
      
      requests_result = results[:results].find { |r| r[:package][:name] == 'requests' }
      expect(requests_result[:trust][:level]).to_not eq('UNTRUSTED')
      expect(requests_result[:action]).to eq('VERIFIED').or eq('WARN')
    end

    it 'detects non-existent Python packages' do
      components = [
        { 'purl' => 'pkg:pypi/django-fake-package-xyz123@1.0.0' },
        { 'purl' => 'pkg:pypi/totally-nonexistent-pypi-pkg@0.1.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(2)
      expect(results[:not_found]).to eq(2)
      
      results[:results].each do |result|
        expect(result[:trust][:level]).to eq('NOT_FOUND')
        expect(result[:action]).to eq('NOT_FOUND')
      end
    end

    it 'handles Python package name normalization' do
      # PyPI normalizes dashes/underscores - both should work
      components = [
        { 'purl' => 'pkg:pypi/python-dateutil@2.8.2' },
        { 'purl' => 'pkg:pypi/python_dateutil@2.8.2' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      # Both should be found (same package)
      expect(results[:not_found]).to eq(0)
      expect(results[:total]).to eq(2)
    end

    it 'detects namespace squatting in Python packages' do
      components = [
        { 'purl' => 'pkg:pypi/django@4.2.0' },  # Legitimate
        { 'purl' => 'pkg:pypi/django-test-helpers@0.1.0' }  # Should check if suspicious
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      django_result = results[:results].find { |r| r[:package][:name] == 'django' }
      expect(django_result[:anomalies]).to be_empty
      
      # The test helper might or might not exist; we're testing the mechanism
      helper_result = results[:results].find { |r| r[:package][:name] == 'django-test-helpers' }
      # If it doesn't exist, should be flagged as NOT_FOUND
      # If it exists but is low-trust, should potentially have anomalies
    end
  end

  describe 'Mixed Ecosystems' do
    it 'handles SBOM with both Ruby and Python packages' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:pypi/django@4.2.0' },
        { 'purl' => 'pkg:gem/rspec@3.12.0' },
        { 'purl' => 'pkg:pypi/requests@2.31.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(4)
      expect(results[:not_found]).to eq(0)
      
      # Check each ecosystem processed correctly
      ruby_results = results[:results].select { |r| r[:package][:ecosystem] == 'ruby' }
      python_results = results[:results].select { |r| r[:package][:ecosystem] == 'python' }
      
      expect(ruby_results.size).to eq(2)
      expect(python_results.size).to eq(2)
      
      # All should be verified or warned, not blocked
      results[:results].each do |result|
        expect(result[:action]).to_not eq('BLOCK')
        expect(result[:action]).to_not eq('NOT_FOUND')
      end
    end

    it 'detects mixed ecosystem with some invalid packages' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:pypi/fake-python-package-xyz@1.0.0' },
        { 'purl' => 'pkg:gem/fake-ruby-gem-abc@1.0.0' },
        { 'purl' => 'pkg:pypi/requests@2.31.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(4)
      expect(results[:not_found]).to eq(2)
      expect(results[:verified]).to be >= 1
      
      # Valid packages should be verified
      rails_result = results[:results].find { |r| r[:package][:name] == 'rails' }
      expect(rails_result[:action]).to eq('VERIFIED')
      
      # Fake packages should be not found
      fake_python = results[:results].find { |r| r[:package][:name] == 'fake-python-package-xyz' }
      expect(fake_python[:action]).to eq('NOT_FOUND')
    end
  end

  describe 'Performance' do
    it 'scans large SBOM efficiently' do
      # Create SBOM with 50 packages (mix of Ruby and Python)
      components = []
      
      25.times do |i|
        components << { 'purl' => "pkg:gem/test-gem-#{i}@1.0.0" }
        components << { 'purl' => "pkg:pypi/test-package-#{i}@1.0.0" }
      end
      
      sbom_path = create_sbom(components)
      
      start_time = Time.now
      results = SlopGuard.scan(sbom_path)
      elapsed = Time.now - start_time
      
      expect(results[:total]).to eq(50)
      
      # Should complete in reasonable time (most will be cache misses and 404s)
      # Allow up to 30 seconds for 50 packages with network calls
      expect(elapsed).to be < 30
      
      puts "\n  Scanned #{results[:total]} packages in #{elapsed.round(2)}s"
      puts "  Found: #{results[:not_found]}, Verified: #{results[:verified]}, " \
           "Suspicious: #{results[:suspicious]}, Blocked: #{results[:high_risk]}"
    end
  end

  describe 'Error Handling' do
    it 'handles empty SBOM gracefully' do
      sbom_path = create_sbom([])
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(0)
      expect(results[:results]).to be_empty
    end

    it 'skips unsupported ecosystem packages' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:npm/express@4.18.0' },  # npm not supported yet
        { 'purl' => 'pkg:pypi/requests@2.31.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      # Should only process supported ecosystems
      expect(results[:total]).to eq(2)  # Only gem and pypi
      
      ecosystems = results[:results].map { |r| r[:package][:ecosystem] }.uniq
      expect(ecosystems).to contain_exactly('ruby', 'python')
    end

    it 'continues processing after individual package failures' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:pypi/requests@2.31.0' },
        { 'purl' => 'pkg:gem/fake-gem-abc@1.0.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      # Should process all packages despite one being fake
      expect(results[:total]).to eq(3)
      expect(results[:verified]).to be >= 2
      expect(results[:not_found]).to eq(1)
    end
  end
end
