$LOAD_PATH.unshift(File.expand_path("../../", __FILE__))
require "test-unit"
require "fluent/test"
require "fluent/test/driver/filter"
require "fluent/test/helpers"

Test::Unit::TestCase.include(Fluent::Test::Helpers)
Test::Unit::TestCase.extend(Fluent::Test::Helpers)

def pem_key_path(filename)
    File.join(
        File.dirname(__FILE__),
        "fixtures/#{filename}.pem"
    )
end

def private_key_path(algorithm)
    pem_key_path("#{algorithm}/private_key")
end

def public_key_path(algorithm)
    pem_key_path("#{algorithm}/public_key")
end