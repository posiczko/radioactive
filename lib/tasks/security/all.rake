desc "Run all security checks (bundler-audit and gitleaks)"
task security: %w[security:audit security:gitleaks]
