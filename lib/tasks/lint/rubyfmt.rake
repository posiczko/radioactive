namespace :lint do
  desc "Run rubyfmt formatter check"
  task :rubyfmt do
    sh "rubyfmt --check ."
  end

  namespace :rubyfmt do
    desc "Run rubyfmt autocorrect"
    task :autocorrect do
      sh "rubyfmt --in-place ."
    end
  end
end
