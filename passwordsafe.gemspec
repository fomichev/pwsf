$LOAD_PATH.push File.expand_path("../lib", __FILE__)
require 'passwordsafe'

Gem::Specification.new do |s|
  s.name = 'pwsf'
  s.version = PasswordSafe::VERSION
  s.platform = Gem::Platform::RUBY
  s.authors = [ 'Stanislav Fomichev' ]
  s.email = [ 's@fomichev.me' ]
  s.homepage = 'http://github.com/fomichev/passwordsafe'
  s.summary = 'PasswordSafe (passwordsafe.sourceforge.net) command-line client.'
  s.description = ''

  s.rubyforge_project = 'pwsf'

  s.has_rdoc = true
  s.files = `git ls-files -z`.split("\0")
  s.require_paths << 'lib'
  s.executables = [ 'pwsf' ]
  s.extra_rdoc_files = [ 'README.rdoc', 'LICENSE' ]

  s.add_dependency('clipboard')
end
