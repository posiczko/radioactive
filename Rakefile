# frozen_string_literal: true

require "minitest/test_task"

Dir.glob("lib/tasks/**/*.rake").each { |r| load r }

Minitest::TestTask.create

task default: %i[test lint types]
desc "Run linter"
task lint: "lint:all"
