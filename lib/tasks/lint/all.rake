namespace :lint do
  desc "Run all linter checks"
  task all: %i[rubocop] do
    puts "All lints completed successfully!"
  end

  namespace :all do
    desc "Run all linter autocorrects"
    task autocorrect: %i[rubocop:autocorrect]
  end
end
