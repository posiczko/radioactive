# frozen_string_literal: true

require_relative "lib/radioactive/version"

Gem::Specification.new do |spec|
  spec.name = "radioactive"
  spec.version = Radioactive::VERSION
  spec.authors = ["Pawel Osiczko"]
  spec.email = ["p.osiczko@tetrapyloctomy.org"]

  spec.summary = "Hardened HTTP fetcher for Ruby. Safe to point at URLs supplied by untrusted users."
  spec.description = <<~DESC
    Radioactive wraps Net::HTTP with defenses against SSRF, DNS rebinding,
    slowloris, response and decompression bombs, redirect chains into private
    addresses, and disallowed schemes. Safe-by-default for use cases like link
    previews, image proxies, webhook delivery, and metadata extraction from
    user-supplied URLs.
  DESC
  spec.homepage = "https://github.com/posiczko/radioactive"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"
  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}#readme"

  # Require MFA for pushes to defend the supply chain. A leaked or stolen
  # rubygems API key alone cannot publish a new version.
  # https://guides.rubygems.org/mfa-requirement-opt-in/
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ docs/ Gemfile .gitignore test/ .github/ .rubocop.yml])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency("zeitwerk")
end
