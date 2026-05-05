require "rubocop/rake_task"

namespace :lint do
  desc "Run rubocop linter check"
  task :rubocop do
    exec "bundle exec rubocop"
  end

  namespace :rubocop do
    desc "Run rubocop autocorrect"
    task :autocorrect do
      exec "bundle exec rubocop --autocorrect-all"
    end
  end
end
