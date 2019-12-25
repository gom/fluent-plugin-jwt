require "helper"
require "fluent/plugin/filter_jwt_sign.rb"

class JwtSignFilterTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
    @tag = "input.access"
    @key = 'claim'
    @target_key = 'id_token'
    @messages = [
      { "foo" => 'bar', @key =>
        { 
          'iss' => 'http://example.com',
          'aud' => 'cc',
          'sub' => 'a_user_id'
        }
      }
    ]
  end

  sub_test_case "valid sign" do
    data(
      ecdsa: [:ecdsa],
      rsa: [:rsa]
    )
    test "sign with a template case" do
      alg, _ = data
      config = %[
        key #{@key}
        remove_key true
        target_key #{@target_key}

        key_algorithm #{alg}
        private_key_file #{private_key_path(alg)}
      ]

     filter(config, @messages).each do |record|
        assert_true(record.has_key? @target_key)
        assert_true(record[@target_key].start_with? 'eyJ')
        assert_false(record.has_key? @key)
      end
    end

    data(
      ecdsa: [:ecdsa],
      rsa: [:rsa]
    )
    test "sign without remove_key" do
      alg, _ = data
      config = %[
        key #{@key}
        target_key #{@target_key}

        key_algorithm #{alg}
        private_key_file #{private_key_path(alg)}
      ]

      filter(config, @messages).each do |record|
        assert_true(record.has_key? @target_key)
        assert_true(record[@target_key].start_with? 'eyJ')
        assert_true(record.has_key? @key)
        assert_equal(record[@key], @messages[0][@key])
      end
    end

    test "no sign when the key does not exist in the record" do
      config = %[
        key #{@key}
        target_key #{@target_key}

        private_key_file #{private_key_path(:ecdsa)}
      ]
      messages = [{'foo' => 'bar'}]
      filter(config, messages).each do |record|
        assert_false(record.has_key? @target_key)
        assert_equal(record, messages[0])
      end
    end
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::JwtSignFilter).configure(conf)
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
