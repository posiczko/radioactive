namespace :security do
  desc "Scan the working tree for secrets with gitleaks"
  task :gitleaks do
    sh "gitleaks dir --no-banner --redact ."
  end
end
