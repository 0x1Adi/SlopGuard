require_relative '../lib/slopguard'
require 'json'

RSpec.describe SlopGuard::Reporter do
  let(:results) do
    {
      total: 3,
      verified: 1,
      suspicious: 0,
      high_risk: 1,
      not_found: 1,
      results: [  # This is the correct key name
        {
          package: { name: 'fake-pkg', version: '1.0.0', ecosystem: 'ruby' },
          trust: { score: 0, level: 'NOT_FOUND', breakdown: [], stage: 0 },
          anomalies: [],
          action: 'NOT_FOUND'
        },
        {
          package: { name: 'suspicious-pkg', version: '2.0.0', ecosystem: 'python' },
          trust: { 
            score: 25, 
            level: 'UNTRUSTED', 
            breakdown: [{ signal: 'age', points: 25, reason: 'Mature (2+ years)' }],
            stage: 3
          },
          anomalies: [
            { type: 'namespace_squat', severity: 'HIGH', description: "Uses 'requests' namespace" }
          ],
          action: 'BLOCK'
        },
        {
          package: { name: 'rails', version: '7.0.0', ecosystem: 'ruby' },
          trust: {
            score: 95,
            level: 'CRITICAL',
            breakdown: [
              { signal: 'downloads', points: 30, reason: 'Critical infrastructure' },
              { signal: 'age', points: 15, reason: 'Mature' }
            ],
            stage: 1
          },
          anomalies: [],
          action: 'VERIFIED'
        }
      ]
    }
  end
  
  describe 'text format' do
    it 'includes summary statistics' do
      report = described_class.generate(results, format: :text)
      
      expect(report).to include('Total packages:     3')
      expect(report).to include('✓ Verified:         1')
      expect(report).to include('✗ High risk:        1')
      expect(report).to include('? Not found:        1')
    end
    
    it 'lists not found packages' do
      report = described_class.generate(results, format: :text)
      
      expect(report).to include('NON-EXISTENT PACKAGES')
      expect(report).to include('fake-pkg@1.0.0')
    end
    
    it 'lists high risk packages with anomalies' do
      report = described_class.generate(results, format: :text)
      
      expect(report).to include('HIGH RISK PACKAGES')
      expect(report).to include('suspicious-pkg@2.0.0')
      expect(report).to include('Trust Score: 25/100')
      expect(report).to include('namespace_squat')
    end
    
    it 'lists verified packages by ecosystem' do
      report = described_class.generate(results, format: :text)
      
      expect(report).to include('VERIFIED PACKAGES')
      expect(report).to include('RUBY:')
      expect(report).to include('rails@7.0.0')
    end
    
    it 'shows appropriate summary message' do
      report = described_class.generate(results, format: :text)
      
      expect(report).to include('FAILED')
      expect(report).to include('Found 1 high-risk and 1 non-existent packages')
    end
  end
  
  describe 'JSON format' do
    it 'returns valid JSON' do
      report = described_class.generate(results, format: :json)
      parsed = JSON.parse(report)
      
      expect(parsed).to have_key('total')
      expect(parsed).to have_key('verified')
      expect(parsed).to have_key('results')
    end
    
    it 'preserves all result data' do
      report = described_class.generate(results, format: :json)
      parsed = JSON.parse(report, symbolize_names: true)
      
      expect(parsed[:total]).to eq(3)
      expect(parsed[:verified]).to eq(1)
      expect(parsed[:results].size).to eq(3)
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
    end
    
    it 'includes scanner metadata' do
      scan = gitlab_report[:scan]
      
      expect(scan[:scanner][:id]).to eq('slopguard')
      expect(scan[:type]).to eq('dependency_scanning')
      expect(scan[:status]).to eq('success')
    end
    
    it 'excludes verified packages from vulnerabilities' do
      vulns = gitlab_report[:vulnerabilities]
      
      # Should only include NOT_FOUND and BLOCK actions
      expect(vulns.size).to eq(2)
      expect(vulns.none? { |v| v.dig(:location, :dependency, :package, :name) == 'rails' }).to be true
    end
  end
end
