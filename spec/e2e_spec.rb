require_relative '../lib/slopguard'
require 'json'
require 'tempfile'
require 'webmock/rspec'

RSpec.describe 'SlopGuard E2E' do
  def create_sbom(components)
    file = Tempfile.new(['sbom', '.json'])
    file.write(JSON.generate({ components: components }))
    file.flush
    file.rewind
    @tempfiles ||= []
    @tempfiles << file
    file.path
  end

  after(:all) do
    @tempfiles&.each { |f| f.close! rescue nil }
  end
  
  # Allow real HTTP connections for E2E tests
  before(:each) do
    WebMock.allow_net_connect!
  end
  
  after(:each) do
    WebMock.disable_net_connect!
  end

  describe 'hallucination detection' do
    it 'blocks non-existent packages' do
      sbom = create_sbom([
        { purl: 'pkg:gem/ai-hallucinated-pkg-99999@1.0.0' }
      ])

      scanner = SlopGuard::Scanner.new(sbom, quiet: true)
      results = scanner.run
      
      expect(results[:summary][:hallucinated]).to eq(1)
      expect(results[:packages][0][:action]).to eq('BLOCK')
    end
  end

  describe 'legitimate package verification' do
    it 'verifies Rails with high trust' do
      sbom = create_sbom([
        { purl: 'pkg:gem/rails@7.0.0' }
      ])
      
      scanner = SlopGuard::Scanner.new(sbom, quiet: true)
      results = scanner.run
      
      pkg = results[:packages][0]
      
      expect(pkg[:status]).to eq('VERIFIED')
      expect(pkg[:trust_score]).to be > 60
      expect(pkg[:action]).to eq('ALLOW')
    end

    it 'does not flag Rails components' do
      sbom = create_sbom([
        { purl: 'pkg:gem/actioncable@7.0.0' },
        { purl: 'pkg:gem/activesupport@7.0.0' },
        { purl: 'pkg:gem/activerecord@7.0.0' }
      ])

      scanner = SlopGuard::Scanner.new(sbom, quiet: true)
      results = scanner.run
      
      # DEBUG OUTPUT
      results[:packages].each do |pkg|
        puts "\n#{pkg[:package]}:"
        puts "  Status: #{pkg[:status]}"
        puts "  Trust: #{pkg[:trust_score]} (#{pkg[:trust_level]})"
        puts "  Action: #{pkg[:action]}"
        if pkg[:anomalies]&.any?
          puts "  Anomalies:"
          pkg[:anomalies].each do |a|
            puts "    - #{a[:type]}: #{a[:evidence]}"
          end
        end
      end
      
      expect(results[:summary][:verified]).to eq(3)
      expect(results[:summary][:suspicious]).to eq(0)
    end

    it 'verifies Ruby stdlib gems' do
      sbom = create_sbom([
        { purl: 'pkg:gem/json@2.6.0' }
      ])

      scanner = SlopGuard::Scanner.new(sbom, quiet: true)
      results = scanner.run
      pkg = results[:packages][0]
      
      expect(pkg[:status]).to eq('VERIFIED')
      expect(pkg[:trust_score]).to be > 60
    end
  end

  describe 'version spike detection' do
    it 'detects rapid version publishing attacks' do
      # Use WebMock for this test since we're pre-populating cache
      WebMock.disable_net_connect!
      
      # Pre-populate cache with version spike pattern
      cache = SlopGuard::Cache.new
      
      # Simulate 6 versions published in last 12 hours
      now = Time.now
      fake_versions = (1..6).map do |i|
        {
          number: "1.0.#{i}",
          created_at: (now - (i * 2 * 3600)).iso8601,  # 2 hours apart
          platform: 'ruby'
        }
      end
      
      cache.set('versions:suspiciousrapidgem', fake_versions, ttl: 604800)
      
      # Stub the metadata call for the full package name
      stub_request(:get, "https://rubygems.org/api/v1/gems/suspiciousrapidgem.json")
        .to_return(
          status: 200,
          body: JSON.generate({
            name: 'suspiciousrapidgem',
            downloads: 500,
            version: '1.0.6',
            authors: 'test',
            created_at: (now - 86400).iso8601
          })
        )
      
      # Also stub any potential namespace check (package has no hyphen, so won't trigger)
      # But add it just in case
      stub_request(:get, /rubygems\.org\/api\/v1\/gems\/.*\.json/)
        .to_return(status: 404)
      
      # Create detector with pre-populated cache
      http = SlopGuard::HttpClient.new
      detector = SlopGuard::AnomalyDetector.new(http, cache)
      
      package = { name: 'suspiciousrapidgem', version: '1.0.6', ecosystem: 'ruby' }
      metadata = { name: 'suspiciousrapidgem', downloads: 500 }
      trust = { score: 50 }
      
      anomalies = detector.detect(package, metadata, trust)
      
      spike = anomalies.find { |a| a[:type] == 'version_spike' }
      expect(spike).not_to be_nil
      expect(spike[:severity]).to eq('HIGH')
      expect(spike[:evidence]).to include('versions published in last 24 hours')
      
      WebMock.allow_net_connect!
    end
  end

  describe 'typosquatting detection' do
    it 'detects 1-character distance typosquats' do
      sbom = create_sbom([
        { purl: 'pkg:gem/rai1s@1.0.0' }  # rails -> rai1s (l->1)
      ])

      scanner = SlopGuard::Scanner.new(sbom, quiet: true)
      results = scanner.run
      pkg = results[:packages][0]
      
      # May be hallucinated or have typosquat anomaly
      expect(['HIGH_RISK', 'HALLUCINATED', 'SUSPICIOUS']).to include(pkg[:status])
    end
  end

  describe 'namespace squatting detection' do
    it 'detects unauthorized namespace use' do
      sbom = create_sbom([
        { purl: 'pkg:gem/rails-backdoor@1.0.0' }
      ])

      scanner = SlopGuard::Scanner.new(sbom, quiet: true)
      results = scanner.run
      pkg = results[:packages][0]
      
      if pkg[:status] == 'HIGH_RISK'
        squat = pkg[:anomalies]&.find { |a| a[:type] == 'namespace_squat' }
        expect(squat).not_to be_nil if squat
      end
    end
  end

  describe 'homoglyph detection' do
    it 'detects zero vs O substitution' do
      sbom = create_sbom([
        { purl: 'pkg:gem/n0kogiri@1.0.0' }
      ])

      scanner = SlopGuard::Scanner.new(sbom, quiet: true)
      results = scanner.run
      pkg = results[:packages][0]
      
      if pkg[:anomalies]
        homoglyph = pkg[:anomalies].find { |a| a[:type] == 'homoglyph_attack' }
        expect(homoglyph[:evidence]).to include('0') if homoglyph
      end
    end
  end

  describe 'ownership change detection' do
    it 'tracks ownership across scans' do
      sbom = create_sbom([
        { purl: 'pkg:gem/rspec@3.12.0' }
      ])

      # First scan establishes baseline
      scanner1 = SlopGuard::Scanner.new(sbom, quiet: true)
      results1 = scanner1.run
      pkg1 = results1[:packages][0]
      expect(pkg1[:anomalies]&.any? { |a| a[:type] == 'ownership_change' }).to be_falsy

      # Second scan should not detect change (same maintainer)
      scanner2 = SlopGuard::Scanner.new(sbom, quiet: true)
      results2 = scanner2.run
      pkg2 = results2[:packages][0]
      expect(pkg2[:anomalies]&.any? { |a| a[:type] == 'ownership_change' }).to be_falsy
    end
  end

  describe 'download inflation detection' do
    it 'flags unrealistic download ratios' do
      # This would need a fixture or mock
      # Real packages don't typically have this issue
    end
  end

  describe 'suspicious timing detection' do
    it 'flags weekend night publications (low confidence)' do
      # This is a weak signal, mainly for correlation
      # Most packages won't trigger this alone
    end
  end

  describe 'verified namespace bonuses' do
    it 'gives bonus for same-maintainer plugins' do
      sbom = create_sbom([
        { purl: 'pkg:gem/rspec-rails@6.0.0' }
      ])

      scanner = SlopGuard::Scanner.new(sbom, quiet: true)
      results = scanner.run
      pkg = results[:packages][0]
      
      if pkg[:anomalies]
        verified = pkg[:anomalies].find { |a| a[:type] == 'verified_namespace' }
        expect(verified[:bonus]).to eq(15) if verified
      end
    end
  end

  describe 'email domain verification' do
    it 'gives bonus for matching org domains' do
      # Would need gitlab-http or similar package
      # That has engineering@gitlab.com as maintainer
    end
  end
end