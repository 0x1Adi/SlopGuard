require_relative '../lib/slopguard'
require 'json'
require 'tmpdir'

RSpec.describe SlopGuard::Parser do
  let(:temp_dir) { Dir.mktmpdir }
  
  after { FileUtils.rm_rf(temp_dir) }
  
  # FIXED: Helper now creates valid CycloneDX SBOM with required fields
  def create_test_sbom(components)
    sbom = {
      'bomFormat' => 'CycloneDX',
      'specVersion' => '1.4',
      'version' => 1,
      'components' => components
    }
    
    path = File.join(temp_dir, 'test-sbom.json')
    File.write(path, JSON.generate(sbom))
    path
  end
  
  describe 'Ruby PURL parsing' do
    [
      ['pkg:gem/rails@7.0.0', { name: 'rails', version: '7.0.0', ecosystem: 'ruby' }],
      ['pkg:gem/rspec@3.12.0', { name: 'rspec', version: '3.12.0', ecosystem: 'ruby' }],
      ['pkg:gem/nokogiri@1.15.0', { name: 'nokogiri', version: '1.15.0', ecosystem: 'ruby' }]
    ].each do |purl, expected|
      it "parses #{purl}" do
        sbom_path = create_test_sbom([{ 'purl' => purl }])
        parser = described_class.new(sbom_path)
        
        results = parser.parse
        
        expect(results).to be_an(Array)
        expect(results.size).to eq(1)
        expect(results.first).to include(expected)
      end
    end
  end
  
  describe 'Python PURL parsing' do
    [
      ['pkg:pypi/requests@2.31.0', { name: 'requests', version: '2.31.0', ecosystem: 'python' }],
      ['pkg:pypi/django@4.2.0', { name: 'django', version: '4.2.0', ecosystem: 'python' }],
      ['pkg:pypi/numpy@1.26.0', { name: 'numpy', version: '1.26.0', ecosystem: 'python' }],
      ['pkg:pypi/python-dateutil@2.8.2', { name: 'python-dateutil', version: '2.8.2', ecosystem: 'python' }]
    ].each do |purl, expected|
      it "parses #{purl}" do
        sbom_path = create_test_sbom([{ 'purl' => purl }])
        parser = described_class.new(sbom_path)
        
        results = parser.parse
        
        expect(results).to be_an(Array)
        expect(results.size).to eq(1)
        expect(results.first).to include(expected)
      end
    end
  end
  
  describe 'multiple components' do
    it 'parses multiple packages from same ecosystem' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.0.0' },
        { 'purl' => 'pkg:gem/rspec@3.12.0' },
        { 'purl' => 'pkg:gem/nokogiri@1.15.0' }
      ]
      
      sbom_path = create_test_sbom(components)
      parser = described_class.new(sbom_path)
      
      results = parser.parse
      
      expect(results.size).to eq(3)
      expect(results.map { |r| r[:name] }).to contain_exactly('rails', 'rspec', 'nokogiri')
    end
    
    it 'parses mixed ecosystems' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.0.0' },
        { 'purl' => 'pkg:pypi/django@4.2.0' },
        { 'purl' => 'pkg:golang/github.com/gin-gonic/gin@v1.9.0' }
      ]
      
      sbom_path = create_test_sbom(components)
      parser = described_class.new(sbom_path)
      
      results = parser.parse
      
      expect(results.size).to eq(3)
      expect(results.map { |r| r[:ecosystem] }).to contain_exactly('ruby', 'python', 'golang')
    end
  end
  
  describe 'invalid input handling' do
    it 'ignores components without PURL' do
      components = [
        { 'name' => 'some-component', 'version' => '1.0.0' },  # No PURL
        { 'purl' => 'pkg:gem/rails@7.0.0' }
      ]
      
      sbom_path = create_test_sbom(components)
      parser = described_class.new(sbom_path)
      
      results = parser.parse
      
      expect(results.size).to eq(1)
      expect(results.first[:name]).to eq('rails')
    end
    
    it 'ignores unsupported ecosystem PURLs' do
      components = [
        { 'purl' => 'pkg:maven/org.springframework/spring-core@5.3.0' },  # Unsupported
        { 'purl' => 'pkg:gem/rails@7.0.0' }
      ]
      
      sbom_path = create_test_sbom(components)
      parser = described_class.new(sbom_path)
      
      results = parser.parse
      
      expect(results.size).to eq(1)
      expect(results.first[:name]).to eq('rails')
    end
    
    it 'returns empty array for empty SBOM' do
      sbom_path = create_test_sbom([])
      parser = described_class.new(sbom_path)
      
      results = parser.parse
      
      expect(results).to eq([])
    end
  end
  
  describe 'version format variations' do
    [
      '7.0.0',
      '7.0.0.alpha',
      '7.0.0-beta.1',
      '1.2.3.4',
      '2.31.0',
      '4.2.0rc1'
    ].each do |version|
      it "handles version #{version}" do
        sbom_path = create_test_sbom([{ 'purl' => "pkg:gem/rails@#{version}" }])
        parser = described_class.new(sbom_path)
        
        results = parser.parse
        
        expect(results.size).to eq(1)
        expect(results.first[:version]).to eq(version)
      end
    end
  end
  
  describe 'deduplication' do
    it 'removes duplicate packages' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.0.0' },
        { 'purl' => 'pkg:gem/rails@7.0.0' },  # Duplicate
        { 'purl' => 'pkg:gem/rspec@3.12.0' }
      ]
      
      sbom_path = create_test_sbom(components)
      parser = described_class.new(sbom_path)
      
      results = parser.parse
      
      expect(results.size).to eq(2)
      expect(results.map { |r| r[:name] }).to contain_exactly('rails', 'rspec')
    end
  end
  
  describe 'input validation' do
    it 'raises error for non-existent file' do
      parser = described_class.new('/nonexistent/path/sbom.json')
      
      expect { parser.parse }.to raise_error(SlopGuard::Parser::ParseError, /SBOM file does not exist/)
    end
    
    it 'raises error for invalid JSON' do
      path = File.join(temp_dir, 'invalid.json')
      File.write(path, 'not valid json {')
      
      parser = described_class.new(path)
      
      expect { parser.parse }.to raise_error(SlopGuard::Parser::ParseError, /Invalid JSON/)
    end
    
    it 'raises error for empty file' do
      path = File.join(temp_dir, 'empty.json')
      File.write(path, '')
      
      parser = described_class.new(path)
      
      expect { parser.parse }.to raise_error(SlopGuard::Parser::ParseError, /empty/)
    end
    
    it 'raises error for non-CycloneDX format' do
      sbom = {
        'bomFormat' => 'SPDX',  # Wrong format
        'specVersion' => '2.2'
      }
      
      path = File.join(temp_dir, 'spdx.json')
      File.write(path, JSON.generate(sbom))
      
      parser = described_class.new(path)
      
      expect { parser.parse }.to raise_error(SlopGuard::Parser::ParseError, /Unsupported BOM format/)
    end
    
    it 'raises error for missing specVersion' do
      sbom = {
        'bomFormat' => 'CycloneDX'
        # Missing specVersion
      }
      
      path = File.join(temp_dir, 'no-version.json')
      File.write(path, JSON.generate(sbom))
      
      parser = described_class.new(path)
      
      expect { parser.parse }.to raise_error(SlopGuard::Parser::ParseError, /Missing specVersion/)
    end
  end
  
  describe 'name sanitization' do
    it 'removes special characters from package names' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.0.0' }  # Normal name
      ]
      
      sbom_path = create_test_sbom(components)
      parser = described_class.new(sbom_path)
      
      results = parser.parse
      
      expect(results.first[:name]).to match(/^[\w\-\.\/\@]+$/)
    end
    
    it 'removes special characters from versions' do
      components = [
        { 'purl' => 'pkg:gem/rails@7.0.0' }  # Normal version
      ]
      
      sbom_path = create_test_sbom(components)
      parser = described_class.new(sbom_path)
      
      results = parser.parse
      
      expect(results.first[:version]).to match(/^[\w\-\.\+]+$/)
    end
  end
end
