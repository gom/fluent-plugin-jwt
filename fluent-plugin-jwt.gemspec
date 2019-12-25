lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name    = "fluent-plugin-jwt"
  spec.version = "0.0.1"
  spec.authors = ["gom"]
  spec.email   = ["gomgom68@gmail.com"]

  spec.summary       = %q{Fluent Filter plugin to sign and decode Json Web Token (JWT).}
  spec.description   = %q{Fluent Filter plugin to sign and decode Json Web Token (JWT).}
  spec.homepage      = "https://github.com/gom/fluent-plugin-jwt"
  spec.license       = "Apache-2.0"

  test_files, files  = `git ls-files -z`.split("\x0").partition do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.files         = files
  spec.executables   = files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = test_files
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 12.0"
  spec.add_development_dependency "test-unit", "~> 3.0"
  spec.add_runtime_dependency "fluentd", [">= 0.14.10", "< 2"]
  spec.add_runtime_dependency 'json-jwt', '>= 1.11.0'
end
