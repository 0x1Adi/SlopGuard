require 'webmock/rspec'

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups
  
  # Disable real HTTP requests during tests
  WebMock.disable_net_connect!(allow_localhost: true)
  
  # Clean up temp files after all tests
  config.after(:suite) do
    cache_dir = File.expand_path('~/.slopguard/cache')
    FileUtils.rm_rf(cache_dir) if File.exist?(cache_dir)
  end
end
