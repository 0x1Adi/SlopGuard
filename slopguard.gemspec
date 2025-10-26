Gem::Specification.new do |spec|
  spec.name          = "slopguard"
  spec.version       = "0.1.0"
  spec.authors       = ["Aditya Tiwari"]
  spec.email         = ["adityatiwari01933@gmail.com"]

  spec.summary       = "Detects AI-hallucinated package dependencies and supply chain attacks"
  spec.description   = "SlopGuard scans SBOMs for typosquatting, slopsquatting, and supply chain attacks using trust scoring and anomaly detection"
  spec.homepage      = "https://github.com/aditya01933/slopguard"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.files         = Dir["lib/**/*.rb", "bin/*", "README.md", "LICENSE"]
  spec.bindir        = "bin"
  spec.executables   = ["slopguard"]
  spec.require_paths = ["lib"]

  spec.add_dependency "concurrent-ruby", "~> 1.2"
  
  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "webmock", "~> 3.18"
  spec.add_development_dependency "vcr", "~> 6.1"
end