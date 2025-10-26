require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec) do |t|
  t.pattern = 'spec/**/*_spec.rb'
  t.rspec_opts = '--format documentation'
end

task default: :spec

desc "Run unit tests only (exclude e2e)"
task :unit do
  system("bundle exec rspec spec/*_spec.rb --exclude-pattern spec/e2e_spec.rb")
end

desc "Run e2e tests only"
task :e2e do
  system("bundle exec rspec spec/e2e_spec.rb")
end

desc "Run tests with coverage report"
task :coverage do
  ENV['COVERAGE'] = 'true'
  Rake::Task[:spec].invoke
end
