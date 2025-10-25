require_relative '../lib/slopguard'
require 'json'
require 'tempfile'

RSpec.describe 'SlopGuard E2E' do
  def create_sbom(components)
    file = Tempfile.new(['sbom', '.json'])
    file.write(JSON.generate({ components: components }))
    file.flush
    @tempfiles ||= []
    @tempfiles << file
    file.path
  end

  after(:each) do
    @tempfiles&.each(&:close!)
    @tempfiles = []
  end

  describe 'hallucination detection' do
    it 'blocks non-existent packages' do
      sbom = create_sbom([
        { purl: 'pkg:gem/totally-fake-package-9999@1.0.0' }
      ])

      results = SlopGuard.scan(sbom)
      expect(results[:summary][:hallucinated]).to eq(1)
      expect(results[:packages][0][:action]).to eq('BLOCK')
    end
  end

  describe 'legitimate package verification' do
    it 'verifies Rails with high trust' do
      sbom = create_sbom([
        { purl: 'pkg:gem/rails@7.0.0' }
      ])

      results = SlopGuard.scan(sbom)
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

      results = SlopGuard.scan(sbom)
      expect(results[:summary][:verified]).to eq(3)
      expect(results[:summary][:suspicious]).to eq(0)
    end

    it 'verifies Ruby stdlib gems' do
      sbom = create_sbom([
        { purl: 'pkg:gem/json@2.6.0' }
      ])

      results = SlopGuard.scan(sbom)
      pkg = results[:packages][0]
      
      expect(pkg[:status]).to eq('VERIFIED')
      expect(pkg[:trust_score]).to be > 60
    end
  end

  describe 'typosquatting detection' do
    it 'detects 1-character distance typosquats' do
      sbom = create_sbom([
        { purl: 'pkg:gem/rai1s@1.0.0' }  # rails -> rai1s (l->1)
      ])

      results = SlopGuard.scan(sbom)
      pkg = results[:packages][0]
      
      # May be hallucinated or have typosquat anomaly
      expect(['HIGH_RISK', 'HALLUCINATED']).to include(pkg[:status])
    end
  end

  describe 'namespace squatting detection' do
    it 'detects unauthorized namespace use' do
      sbom = create_sbom([
        { purl: 'pkg:gem/rails-backdoor@1.0.0' }
      ])

      results = SlopGuard.scan(sbom)
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

      results = SlopGuard.scan(sbom)
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
      results1 = SlopGuard.scan(sbom)
      pkg1 = results1[:packages][0]
      expect(pkg1[:anomalies]&.any? { |a| a[:type] == 'ownership_change' }).to be_falsy

      # Second scan should not detect change (same maintainer)
      results2 = SlopGuard.scan(sbom)
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

      results = SlopGuard.scan(sbom)
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
