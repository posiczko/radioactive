namespace :types do
  desc "Validate RBS syntax in sig/ (catches sigs that reference nonexistent types)"
  task :validate do
    sh "bundle exec rbs " \
       "-r uri -r ipaddr -r stringio -r tempfile -r net-http -r openssl -r resolv -r zlib " \
       "-I sig validate"
  end

  desc "Type-check lib/ against sig/ with Steep (catches sig drift from code)"
  task :check do
    sh "bundle exec steep check"
  end
end

desc "Validate RBS sigs and type-check the implementation"
task types: ["types:validate", "types:check"]
