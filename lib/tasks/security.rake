require "bundler/audit/task"

Bundler::Audit::Task.new

namespace :security do
  desc "Update vulnerability database and run audit"
  task :audit do
    Rake::Task["bundle:audit:update"].invoke
    Rake::Task["bundle:audit"].invoke
  end
end
