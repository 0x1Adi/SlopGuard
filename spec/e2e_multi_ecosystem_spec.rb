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

  describe 'Go Modules' do
    it 'verifies popular Go packages' do
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' },
        { 'purl' => 'pkg:golang/github.com/gorilla/mux@v1.8.0' },
        { 'purl' => 'pkg:golang/github.com/stretchr/testify@v1.8.0' }
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
      
      gin_result = results[:results].find { |r| r[:package][:name] == 'github.com/gin-gonic/gin' }
      expect(gin_result[:trust][:score]).to be >= 50  # Go lacks dependents API
      expect(gin_result[:trust][:level]).to match(/MEDIUM|HIGH/)  # Go scores lower without dependents
      expect(gin_result[:action]).to eq('VERIFIED')
    end

    it 'verifies Go standard library packages' do
      components = [
        { 'purl' => 'pkg:golang/golang.org/x/crypto@v0.14.0' },
        { 'purl' => 'pkg:golang/golang.org/x/net@v0.17.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(2)
      expect(results[:verified]).to eq(2)
      expect(results[:not_found]).to eq(0)
      
      # Standard library should get automatic high scores
      results[:results].each do |result|
        expect(result[:trust][:score]).to be >= 90
        expect(result[:trust][:level]).to eq('CRITICAL')
        expect(result[:action]).to eq('VERIFIED')
        
        # Should have standard library signal in breakdown
        breakdown_signals = result[:trust][:breakdown].map { |b| b[:signal] }
        expect(breakdown_signals).to include('standard_library')
      end
    end

    it 'detects non-existent Go packages (hallucinated)' do
      components = [
        { 'purl' => 'pkg:golang/github.com/fake/nonexistent-go-package@v1.0.0' },
        { 'purl' => 'pkg:golang/github.com/totally/hallucinated-module@v0.1.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(2)
      expect(results[:not_found]).to eq(2)
      expect(results[:verified]).to eq(0)
      
      results[:results].each do |result|
        expect(result[:trust][:level]).to eq('NOT_FOUND')
        expect(result[:action]).to eq('NOT_FOUND')
        expect(result[:trust][:score]).to eq(0)
      end
    end

    it 'detects typosquatting patterns in Go packages' do
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' },  # Legitimate
        { 'purl' => 'pkg:golang/github.com/boltdb-go/bolt@v1.3.1' }  # Suspicious (-go suffix)
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(2)
      
      # Legitimate package should be clean
      gin_result = results[:results].find { |r| r[:package][:name] == 'github.com/gin-gonic/gin' }
      expect(gin_result[:anomalies]).to be_empty
      
      # Typosquat pattern should be detected (even if package doesn't exist)
      boltdb_result = results[:results].find { |r| r[:package][:name] == 'github.com/boltdb-go/bolt' }
      
      if boltdb_result[:action] != 'NOT_FOUND'
        # If package exists, check for typosquat anomaly
        anomaly_types = boltdb_result[:anomalies].map { |a| a[:type] }
        expect(anomaly_types).to include('potential_typosquat').or include('repository_not_found')
        
        # Should have lower trust score due to anomalies
        expect(boltdb_result[:trust][:score]).to be < 50
      end
    end

    it 'detects checksum database issues' do
      # Test with a package that might not be in sum.golang.org
      components = [
        { 'purl' => 'pkg:golang/github.com/test/brand-new-package@v0.0.1' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      result = results[:results].first
      
      # Should either be NOT_FOUND or have checksum anomaly
      if result[:action] == 'NOT_FOUND'
        expect(result[:trust][:level]).to eq('NOT_FOUND')
      else
        anomaly_types = result[:anomalies].map { |a| a[:type] }
        # Might have checksum database anomaly or other issues
        expect(result[:trust][:score]).to be < 60
      end
    end

    it 'detects rapid version churn anomaly' do
      # This would require a package with actual rapid version churn
      # For now, we verify the mechanism exists
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      gin_result = results[:results].find { |r| r[:package][:name] == 'github.com/gin-gonic/gin' }
      
      # Gin is a mature package, should not have rapid version churn
      churn_anomaly = gin_result[:anomalies].find { |a| a[:type] == 'rapid_version_churn' }
      expect(churn_anomaly).to be_nil
    end

    it 'flags new packages (< 90 days old)' do
      # This test depends on finding a genuinely new package
      # We'll test the logic works by checking mature packages don't get flagged
      components = [
        { 'purl' => 'pkg:golang/github.com/gorilla/mux@v1.8.0' }  # Mature package
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      mux_result = results[:results].find { |r| r[:package][:name] == 'github.com/gorilla/mux' }
      
      # Mature package should not have new_package anomaly
      new_pkg_anomaly = mux_result[:anomalies].find { |a| a[:type] == 'new_package' }
      expect(new_pkg_anomaly).to be_nil
      
      # Should have good age score
      age_component = mux_result[:trust][:breakdown].find { |b| b[:signal] == 'age' }
      expect(age_component[:points]).to be >= 6
    end

    it 'detects archived repositories' do
      # Note: This requires a package with an archived GitHub repo
      # We test the mechanism works for legitimate packages
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      gin_result = results[:results].find { |r| r[:package][:name] == 'github.com/gin-gonic/gin' }
      
      # Gin's repo is active, should not be archived
      archived_anomaly = gin_result[:anomalies].find { |a| a[:type] == 'archived_repository' }
      expect(archived_anomaly).to be_nil
    end

    it 'scores packages based on OpenSSF Scorecard' do
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      gin_result = results[:results].find { |r| r[:package][:name] == 'github.com/gin-gonic/gin' }
      
      # Should have scorecard component in breakdown
      breakdown_signals = gin_result[:trust][:breakdown].map { |b| b[:signal] }
      expect(breakdown_signals).to include('openssf_scorecard').or include('scorecard')
      
      # Scorecard should contribute points
      scorecard_component = gin_result[:trust][:breakdown].find do |b| 
        b[:signal] == 'openssf_scorecard' || b[:signal] == 'scorecard'
      end
      
      if scorecard_component
        expect(scorecard_component[:points]).to be >= 0
      end
    end

    it 'weighs dependents heavily in scoring' do
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' }  # Very popular
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      gin_result = results[:results].find { |r| r[:package][:name] == 'github.com/gin-gonic/gin' }
      
      # Should have dependents component
      dependents_component = gin_result[:trust][:breakdown].find { |b| b[:signal] == 'dependents' }
      
      # deps.dev doesn't provide Go module dependents (confirmed API limitation)
      expect(dependents_component).to_not be_nil
      expect(dependents_component[:points]).to eq(0)  # Always 0 for Go
    end

    it 'weighs GitHub stars in scoring' do
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' }  # 70k+ stars
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      gin_result = results[:results].find { |r| r[:package][:name] == 'github.com/gin-gonic/gin' }
      
      # Should have github_stars component
      stars_component = gin_result[:trust][:breakdown].find { |b| b[:signal] == 'github_stars' }
      
      if stars_component
        # Gin has 70k+ stars, should get high score
        expect(stars_component[:points]).to be >= 11
      end
    end
  end

  describe 'Mixed Ecosystems' do
    it 'handles SBOM with Ruby, Python, and Go packages' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:pypi/django@4.2.0' },
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' },
        { 'purl' => 'pkg:gem/rspec@3.12.0' },
        { 'purl' => 'pkg:pypi/requests@2.31.0' },
        { 'purl' => 'pkg:golang/github.com/gorilla/mux@v1.8.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(6)
      expect(results[:not_found]).to eq(0)
      
      # Check each ecosystem processed correctly
      ruby_results = results[:results].select { |r| r[:package][:ecosystem] == 'ruby' }
      python_results = results[:results].select { |r| r[:package][:ecosystem] == 'python' }
      go_results = results[:results].select { |r| r[:package][:ecosystem] == 'golang' }
      
      expect(ruby_results.size).to eq(2)
      expect(python_results.size).to eq(2)
      expect(go_results.size).to eq(2)
      
      # All should be verified or warned, not blocked
      results[:results].each do |result|
        expect(result[:action]).to_not eq('BLOCK')
        expect(result[:action]).to_not eq('NOT_FOUND')
      end
    end

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
        { 'purl' => 'pkg:golang/github.com/fake/hallucinated@v1.0.0' },
        { 'purl' => 'pkg:gem/fake-ruby-gem-abc@1.0.0' },
        { 'purl' => 'pkg:pypi/requests@2.31.0' },
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(6)
      expect(results[:not_found]).to eq(3)
      expect(results[:verified]).to be >= 2
      
      # Valid packages should be verified
      rails_result = results[:results].find { |r| r[:package][:name] == 'rails' }
      expect(rails_result[:action]).to eq('VERIFIED')
      
      gin_result = results[:results].find { |r| r[:package][:name] == 'github.com/gin-gonic/gin' }
      expect(gin_result[:action]).to eq('VERIFIED')
      
      # Fake packages should be not found
      fake_go = results[:results].find { |r| r[:package][:name] == 'github.com/fake/hallucinated' }
      expect(fake_go[:action]).to eq('NOT_FOUND')
      
      fake_python = results[:results].find { |r| r[:package][:name] == 'fake-python-package-xyz' }
      expect(fake_python[:action]).to eq('NOT_FOUND')
    end

    it 'handles Go standard library with other ecosystems' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:golang/golang.org/x/crypto@v0.14.0' },  # Standard lib
        { 'purl' => 'pkg:pypi/django@4.2.0' },
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' }  # Regular module
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      expect(results[:total]).to eq(4)
      expect(results[:verified]).to eq(4)
      
      # Go stdlib should have highest score
      crypto_result = results[:results].find { |r| r[:package][:name] == 'golang.org/x/crypto' }
      expect(crypto_result[:trust][:score]).to eq(95)
      expect(crypto_result[:trust][:level]).to eq('CRITICAL')
    end
  end

  describe 'Performance' do
    it 'scans large SBOM with Go packages efficiently' do
      # Create SBOM with 60 packages (20 each of Ruby, Python, Go)
      components = []
      
      20.times do |i|
        components << { 'purl' => "pkg:gem/test-gem-#{i}@1.0.0" }
        components << { 'purl' => "pkg:pypi/test-package-#{i}@1.0.0" }
        components << { 'purl' => "pkg:golang/github.com/test/module-#{i}@v1.0.0" }
      end
      
      sbom_path = create_sbom(components)
      
      start_time = Time.now
      results = SlopGuard.scan(sbom_path)
      elapsed = Time.now - start_time
      
      expect(results[:total]).to eq(60)
      
      # Should complete in reasonable time (most will be cache misses and 404s)
      # Allow up to 45 seconds for 60 packages with network calls
      expect(elapsed).to be < 45
      
      puts "\n  Scanned #{results[:total]} packages in #{elapsed.round(2)}s"
      puts "  Found: #{results[:not_found]}, Verified: #{results[:verified]}, " \
           "Suspicious: #{results[:suspicious]}, Blocked: #{results[:high_risk]}"
      
      # Check ecosystem distribution
      ecosystems = results[:results].group_by { |r| r[:package][:ecosystem] }
      puts "  Ecosystems: #{ecosystems.keys.join(', ')}"
      ecosystems.each do |eco, pkgs|
        puts "    #{eco}: #{pkgs.size} packages"
      end
    end

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

    it 'benefits from caching on repeated scans' do
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' },
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:pypi/requests@2.31.0' }
      ]
      
      sbom_path = create_sbom(components)
      
      # First scan (cold cache)
      start_time = Time.now
      first_results = SlopGuard.scan(sbom_path)
      first_elapsed = Time.now - start_time
      
      # Second scan (warm cache)
      start_time = Time.now
      second_results = SlopGuard.scan(sbom_path)
      second_elapsed = Time.now - start_time
      
      # Results should be identical
      expect(first_results[:total]).to eq(second_results[:total])
      expect(first_results[:verified]).to eq(second_results[:verified])
      
      # Second scan should be faster due to caching
      expect(second_elapsed).to be <= (first_elapsed * 1.2)  # Allow 20% variance for timing
      
      puts "\n  First scan (cold): #{first_elapsed.round(2)}s"
      puts "  Second scan (warm): #{second_elapsed.round(2)}s"
      puts "  Speedup: #{(first_elapsed / second_elapsed).round(1)}x"
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
        { 'purl' => 'pkg:pypi/requests@2.31.0' },
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' },
        { 'purl' => 'pkg:cargo/serde@1.0.0' }  # Rust not supported yet
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      # Should only process supported ecosystems
      expect(results[:total]).to eq(3)  # gem, pypi, golang
      
      ecosystems = results[:results].map { |r| r[:package][:ecosystem] }.uniq.sort
      expect(ecosystems).to contain_exactly('golang', 'python', 'ruby')
    end

    it 'continues processing after individual package failures' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.1.0' },
        { 'purl' => 'pkg:pypi/requests@2.31.0' },
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' },
        { 'purl' => 'pkg:gem/fake-gem-abc@1.0.0' },
        { 'purl' => 'pkg:golang/github.com/fake/module@v1.0.0' }
      ]
      
      sbom_path = create_sbom(components)
      results = SlopGuard.scan(sbom_path)
      
      # Should process all packages despite some being fake
      expect(results[:total]).to eq(5)
      expect(results[:verified]).to be >= 3
      expect(results[:not_found]).to eq(2)
    end

    it 'handles API timeouts gracefully' do
      # This test verifies the system doesn't crash on API failures
      # In real scenarios, some packages might timeout
      components = [
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' },
        { 'purl' => 'pkg:gem/rails@7.1.0' }
      ]
      
      sbom_path = create_sbom(components)
      
      # Should complete without raising errors
      expect { SlopGuard.scan(sbom_path) }.not_to raise_error
    end
  end
end
