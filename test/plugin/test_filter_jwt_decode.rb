require "helper"
require "fluent/plugin/filter_jwt_decode.rb"

class JwtDecodeFilterTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
    @tag = "input.access"
    @key = 'id_token'
    @target_key = 'payload'
  end

  sub_test_case "decode test" do
    DEFAULT_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6InZjRnU1R2dHeHFFSURjXzh6X1NKMEFJQjZPUzhmeVY3QVprYzdpWEQzV28ifQ.eyJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJhdWQiOiJjYyIsInN1YiI6ImFfdXNlcl9pZCJ9.KltDALJIBaCvbfTMWXkaqWlTEHU1GcE7okeEo-5eQxf8MClhU_TU0X1meenLQY40QBBDvWmfG5Wk3EjIT3rXOA'
    DEFAULT_PAYLOAD = { 
      'iss' => 'http://example.com',
      'aud' => 'cc',
      'sub' => 'a_user_id'
    }

    test "decode and verify id token" do 
      config = %[
        key #{@key}
        remove_key true
        target_key #{@target_key}
        public_key_file #{public_key_path(:ecdsa)}

        <verify>
          iss http://example.com
          aud_key channel
          ignore_nonce true
        </verify>
      ]
      messages = [
        {
          'id_token' => DEFAULT_TOKEN,
          'channel' => 'cc'
        }
      ]
      expected = DEFAULT_PAYLOAD

      filter(config, messages).each do |record|
        assert_true(record.has_key? @target_key)
        assert_equal(record[@target_key], expected)
        assert_false(record.has_key? @key)
      end
    end

    test "decode without remove_key" do 
      config = %[
        key #{@key}
        remove_key false
        target_key #{@target_key}
        public_key_file #{public_key_path(:ecdsa)}

        <verify>
          iss http://example.com
          aud_key channel
          ignore_nonce true
        </verify>
      ]
      messages = [
        {
          'id_token' => DEFAULT_TOKEN,
          'channel' => 'cc'
        }
      ]
      expected = DEFAULT_PAYLOAD

      filter(config, messages).each do |record|
        assert_true(record.has_key? @target_key)
        assert_equal(record[@target_key], expected)
        assert_true(record.has_key? @key)
      end
    end

    test "decode without verify" do 
      config = %[
        key #{@key}
        remove_key true
        target_key #{@target_key}
        public_key_file #{public_key_path(:ecdsa)}
      ]
      messages = [
        {
          'id_token' => DEFAULT_TOKEN,
          'channel' => 'cc'
        }
      ]
      expected = DEFAULT_PAYLOAD

      filter(config, messages).each do |record|
        assert_true(record.has_key? @target_key)
        assert_equal(record[@target_key], expected)
        assert_false(record.has_key? @key)
      end
    end
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::JwtDecodeFilter).configure(conf)
  end

  def filter(config, messages)
    d = create_driver(config)
    d.run(default_tag: @tag) do
        messages.each do |message|
        d.feed(message)
        end
    end
    d.filtered_records
  end
end
