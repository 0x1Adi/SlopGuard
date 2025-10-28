require_relative '../lib/slopguard'
require 'tempfile'
require 'json'

RSpec.describe SlopGuard::Parser do
  def create_sbom(components)
    file = Tempfile.new(['test-sbom', '.json'])
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
  
  describe 'Ruby PURL parsing' do
    [
      ['pkg:gem/rails@7.0.0', 'rails', '7.0.0', 'ruby'],
      ['pkg:gem/rspec@3.12.0', 'rspec', '3.12.0', 'ruby'],
      ['pkg:gem/nokogiri@1.15.0', 'nokogiri', '1.15.0', 'ruby']
    ].each do |purl, expected_name, expected_version, expected_ecosystem|
      it "parses #{purl}" do
        sbom_path = create_sbom([{ purl: purl }])
        parser = described_class.new(sbom_path)
        
        result = parser.parse
        expect(result.size).to eq(1)
        expect(result[0][:name]).to eq(expected_name)
        expect(result[0][:version]).to eq(expected_version)
        expect(result[0][:ecosystem]).to eq(expected_ecosystem)
      end
    end
  end
  
  describe 'Python PURL parsing' do
    [
      ['pkg:pypi/requests@2.31.0', 'requests', '2.31.0', 'python'],
      ['pkg:pypi/django@4.2.0', 'django', '4.2.0', 'python'],
      ['pkg:pypi/numpy@1.26.0', 'numpy', '1.26.0', 'python'],
      ['pkg:pypi/python-dateutil@2.8.2', 'python-dateutil', '2.8.2', 'python']
    ].each do |purl, expected_name, expected_version, expected_ecosystem|
      it "parses #{purl}" do
        sbom_path = create_sbom([{ purl: purl }])
        parser = described_class.new(sbom_path)
        
        result = parser.parse
        expect(result.size).to eq(1)
        expect(result[0][:name]).to eq(expected_name)
        expect(result[0][:version]).to eq(expected_version)
        expect(result[0][:ecosystem]).to eq(expected_ecosystem)
      end
    end
  end
  
  describe 'multiple components' do
    it 'parses multiple packages from same ecosystem' do
      components = [
        { purl: 'pkg:gem/rails@7.0.0' },
        { purl: 'pkg:gem/rspec@3.12.0' },
        { purl: 'pkg:gem/rake@13.0.0' }
      ]
      
      sbom_path = create_sbom(components)
      parser = described_class.new(sbom_path)
      
      result = parser.parse
      expect(result.size).to eq(3)
      expect(result.map { |p| p[:name] }).to contain_exactly('rails', 'rspec', 'rake')
      expect(result.all? { |p| p[:ecosystem] == 'ruby' }).to be true
    end
    
    it 'parses mixed ecosystems' do
      components = [
        { purl: 'pkg:gem/rails@7.0.0' },
        { purl: 'pkg:pypi/django@4.2.0' },
        { purl: 'pkg:gem/rspec@3.12.0' },
        { purl: 'pkg:pypi/requests@2.31.0' }
      ]
      
      sbom_path = create_sbom(components)
      parser = described_class.new(sbom_path)
      
      result = parser.parse
      expect(result.size).to eq(4)
      
      ruby_packages = result.select { |p| p[:ecosystem] == 'ruby' }
      python_packages = result.select { |p| p[:ecosystem] == 'python' }
      
      expect(ruby_packages.size).to eq(2)
      expect(python_packages.size).to eq(2)
    end
  end
  
  describe 'invalid input handling' do
    it 'ignores components without PURL' do
      components = [
        { name: 'no-purl-package' },
        { purl: 'pkg:gem/valid@1.0.0' }
      ]
      
      sbom_path = create_sbom(components)
      parser = described_class.new(sbom_path)
      
      result = parser.parse
      expect(result.size).to eq(1)
      expect(result[0][:name]).to eq('valid')
    end
    
    it 'ignores unsupported ecosystem PURLs' do
      components = [
        { purl: 'pkg:npm/express@4.0.0' },      # npm not supported yet
        { purl: 'pkg:cargo/tokio@1.0.0' },     # cargo not supported yet
        { purl: 'pkg:gem/rails@7.0.0' },       # gem supported
        { purl: 'pkg:pypi/requests@2.31.0' }   # pypi supported
      ]
      
      sbom_path = create_sbom(components)
      parser = described_class.new(sbom_path)
      
      result = parser.parse
      expect(result.size).to eq(2)
      expect(result.map { |p| p[:name] }).to contain_exactly('rails', 'requests')
    end
    
    it 'returns empty array for empty SBOM' do
      sbom_path = create_sbom([])
      parser = described_class.new(sbom_path)
      
      result = parser.parse
      expect(result).to eq([])
    end
  end
  
  describe 'version format variations' do
    [
      ['pkg:gem/rails@7.0.0', '7.0.0'],
      ['pkg:gem/rails@7.0.0.alpha', '7.0.0.alpha'],
      ['pkg:gem/rails@7.0.0-beta.1', '7.0.0-beta.1'],
      ['pkg:gem/rails@1.2.3.4', '1.2.3.4'],
      ['pkg:pypi/requests@2.31.0', '2.31.0'],
      ['pkg:pypi/django@4.2.0rc1', '4.2.0rc1']
    ].each do |purl, expected_version|
      it "handles version #{expected_version}" do
        sbom_path = create_sbom([{ purl: purl }])
        parser = described_class.new(sbom_path)
        
        result = parser.parse
        expect(result[0][:version]).to eq(expected_version)
      end
    end
  end
end