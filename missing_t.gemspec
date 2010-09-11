# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{missing_t}
  s.version = "0.2.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Balint Erdi"]
  s.date = %q{2010-09-11}
  s.default_executable = %q{missing_t}
  s.description = %q{      With missing_t you can easily find all the missing i18n translations in your Rails project.
}
  s.email = %q{balint.erdi@gmail.com}
  s.executables = ["missing_t"]
  s.extra_rdoc_files = [
    "README.markdown"
  ]
  s.files = [
    ".gitignore",
     "CHANGELOG",
     "MIT-LICENSE",
     "README.markdown",
     "Rakefile",
     "VERSION",
     "bin/missing_t",
     "init.rb",
     "lib/missing_t.rb",
     "missing_t.gemspec",
     "spec/missing_t_spec.rb",
     "spec/spec_helper.rb",
     "tasks/missing_t.rake",
     "todos.markdown"
  ]
  s.homepage = %q{http://github.com/balinterdi/missing_t}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.summary = %q{See all the missing I18n translations in your Rails project}
  s.test_files = [
    "spec/missing_t_spec.rb",
     "spec/spec_helper.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end

