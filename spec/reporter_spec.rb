require_relative '../lib/slopguard'
require 'json'

RSpec.describe SlopGuard::Reporter do
  let(:results) do
    {
      packages: [
        {
          package: 'fake-pkg',
          version: '1.0.0',
          status: 'HALLUCINATED',
          trust_score: 0,
          action: 'BLOCK',
          reason: 'Package not found'
        },
        {
          package: 'suspicious-pkg',
          version: '2.0.0',
          status: 'HIGH_RISK',
          trust_score: 25,
          trust_level: 'UNTRUSTED',
          action: 'BLOCK',
          anomalies: [
            { type: 'typosquat', severity: 'HIGH', evidence: '1-char from rails', target_package: 'rails' }
          ],
          breakdown: [
            { signal: 'downloads', points: 5, reason: 'Some users' }
          ]
        },
        {
          package: 'rails',
          version: '7.0.0',
          status: 'VERIFIED',
          trust_score: 95,
          trust_level: 'CRITICAL',
          action: 'ALLOW',
          breakdown: [
            { signal: 'downloads', points: 30, reason: 'Critical infrastructure' },
            { signal: 'age', points: 15, reason: 'Mature' }
          ]
        }
      ],
      summary: {
        total: 3,
        verified: 1,
        suspicious: 0,
        high_risk: 1,
        hallucinated: 1
      }
    }
  end
  
  describe 'text format' do
    it 'includes summary statistics' do
      report = described_class.generate(results, format: :text)
      
      expect(report).to include('Total packages: 3')
      expect(report).to include('Verified: 1')
      expect(report).to include('High risk: 1')
      expect(report).to include('Hallucinated: 1')
    end
    
    it 'lists risky packages' do
      report = described_class.generate(results, format: :text)
      
      # Verified packages should not appear in risky section
      expect(report).not_to include('rails@7.0.0 - VERIFIED')
      
      # High risk and hallucinated should appear (SUSPICIOUS is skipped in output)
      expect(report).to include('fake-pkg@1.0.0 - HALLUCINATED')
      expect(report).to include('suspicious-pkg@2.0.0 - HIGH_RISK')
    end
    
    it 'shows trust scores and anomalies' do
      report = described_class.generate(results, format: :text)
      
      expect(report).to include('Trust score: 0/100')
      expect(report).to include('typosquat')
    end
  end
  
  describe 'JSON format' do
    it 'returns valid JSON' do
      report = described_class.generate(results, format: :json)
      parsed = JSON.parse(report)
      
      expect(parsed).to have_key('packages')
      expect(parsed).to have_key('summary')
    end
    
    it 'preserves all result data' do
      report = described_class.generate(results, format: :json)
      parsed = JSON.parse(report, symbolize_names: true)
      
      expect(parsed[:packages].size).to eq(3)
      expect(parsed[:summary][:total]).to eq(3)
    end
  end
  
  describe 'GitLab format' do
    let(:gitlab_report) do
      JSON.parse(
        described_class.generate(results, sbom_path: 'test.json', format: :gitlab),
        symbolize_names: true
      )
    end
    
    it 'includes required schema fields' do
      expect(gitlab_report[:version]).to eq('15.0.0')
      expect(gitlab_report[:scan]).to be_a(Hash)
      expect(gitlab_report[:vulnerabilities]).to be_an(Array)
      expect(gitlab_report[:dependency_files]).to be_an(Array)
    end
    
    it 'includes scanner metadata' do
      scan = gitlab_report[:scan]
      
      expect(scan[:scanner][:id]).to eq('slopguard')
      expect(scan[:analyzer][:id]).to eq('slopguard')
      expect(scan[:type]).to eq('dependency_scanning')
      expect(scan[:status]).to eq('success')
    end
    
    it 'excludes verified packages from vulnerabilities' do
      vulns = gitlab_report[:vulnerabilities]
      
      expect(vulns.size).to eq(2)  # Only hallucinated and high_risk
      expect(vulns.none? { |v| v[:name].include?('rails') }).to be true
    end
    
    it 'maps statuses to severity correctly' do
      vulns = gitlab_report[:vulnerabilities]
      
      hallucinated = vulns.find { |v| v[:name].include?('fake-pkg') }
      high_risk = vulns.find { |v| v[:name].include?('suspicious-pkg') }
      
      expect(hallucinated[:severity]).to eq('Critical')
      expect(high_risk[:severity]).to eq('High')
    end
    
    it 'includes detailed descriptions' do
      vulns = gitlab_report[:vulnerabilities]
      
      hallucinated = vulns.find { |v| v[:name].include?('fake-pkg') }
      expect(hallucinated[:description]).to include('AI coding assistant')
      expect(hallucinated[:description]).to include('slopsquatting')
      
      high_risk = vulns.find { |v| v[:name].include?('suspicious-pkg') }
      expect(high_risk[:description]).to include('trust score')
      expect(high_risk[:description]).to include('typosquat')
    end
    
    it 'provides actionable solutions' do
      vulns = gitlab_report[:vulnerabilities]
      
      hallucinated = vulns.find { |v| v[:name].include?('fake-pkg') }
      expect(hallucinated[:solution]).to include('Remove it from your dependencies')
      expect(hallucinated[:solution]).to include('verify suggested package names')
      
      high_risk = vulns.find { |v| v[:name].include?('suspicious-pkg') }
      expect(high_risk[:solution]).to include('Remove this package immediately')
    end
    
    it 'includes location information' do
      vulns = gitlab_report[:vulnerabilities]
      vuln = vulns.first
      
      expect(vuln[:location][:file]).to eq('test.json')
      expect(vuln[:location][:dependency][:package][:name]).to be_a(String)
      expect(vuln[:location][:dependency][:version]).to be_a(String)
    end
    
    it 'generates deterministic UUIDs' do
      # Same package should generate same UUID
      uuid1 = gitlab_report[:vulnerabilities][0][:id]
      
      # Generate report again
      report2 = JSON.parse(
        described_class.generate(results, sbom_path: 'test.json', format: :gitlab),
        symbolize_names: true
      )
      uuid2 = report2[:vulnerabilities][0][:id]
      
      expect(uuid1).to eq(uuid2)
      expect(uuid1).to match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
    end
    
    it 'includes valid identifiers with URLs' do
      vulns = gitlab_report[:vulnerabilities]
      vuln = vulns.first
      
      expect(vuln[:identifiers]).to be_an(Array)
      expect(vuln[:identifiers].size).to be > 0
      
      vuln[:identifiers].each do |identifier|
        expect(identifier[:type]).to be_a(String)
        expect(identifier[:name]).to be_a(String)
        expect(identifier[:value]).to be_a(String)
        expect(identifier[:url]).to be_a(String)
        expect(identifier[:url]).to match(/^https?:\/\//)
      end
    end
    
    it 'maps anomaly types to CWE identifiers' do
      vulns = gitlab_report[:vulnerabilities]
      high_risk = vulns.find { |v| v[:name].include?('suspicious-pkg') }
      
      cwe_identifier = high_risk[:identifiers].find { |i| i[:type] == 'cwe' }
      expect(cwe_identifier).not_to be_nil
      expect(cwe_identifier[:name]).to start_with('CWE-')
      expect(cwe_identifier[:url]).to include('cwe.mitre.org')
    end
    
    it 'includes relevant links' do
      vulns = gitlab_report[:vulnerabilities]
      
      vuln = vulns.find { |v| v[:name].include?('suspicious-pkg') }
      expect(vuln[:links]).to be_an(Array)
      expect(vuln[:links].any? { |l| l[:url].include?('rubygems.org') }).to be true
    end
    
    it 'does not include rubygems link for hallucinated packages' do
      vulns = gitlab_report[:vulnerabilities]
      hallucinated = vulns.find { |v| v[:name].include?('fake-pkg') }
      
      rubygems_link = hallucinated[:links].any? { |l| l[:url].include?('rubygems.org') }
      expect(rubygems_link).to be false
    end
  end
end
