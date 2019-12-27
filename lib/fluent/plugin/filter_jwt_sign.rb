require "fluent/plugin/filter"
require "fluent/plugin/jwt_plugin_util"
require 'json/jwt'

module Fluent
  module Plugin
    class JwtSignFilter < Fluent::Plugin::Filter
      include JwtPluginUtil

      Fluent::Plugin.register_filter("jwt_sign", self)

      config_param :private_key_file, :string, :default => "key.pem"
      config_param :key_algorithm, :enum, list: [:ecdsa, :rsa], default: :ecdsa

      config_param :key, :string
      config_param :remove_key, :bool, :default => false
      config_param :target_key, :string

      def configure(conf)
        super
        @jwk = key_file(@private_key_file, @key_algorithm).to_jwk
      end

      def filter(tag, time, record)
        begin
          until record.has_key?(@key)
            log.debug "@key: #{@key} doesn't exist in #{record}"
            return record
          end
          until record[@key].is_a? (Hash)
            log.debug "#{@key} is not a Hash: #{record[@key]}"
            return record
          end

          id_token = JSON::JWT.new(record[@key])
          id_token.kid = @jwk.thumbprint
          id_token = id_token.sign(@jwk.to_key)
          log.debug id_token.to_s

          record[@target_key] = id_token.to_s
          record.delete(@key) if @remove_key
        rescue Exception => e
          log.error "Error", error: e.to_s
          log.debug_backtrace(e.backtrace)
        end

        record
      end
    end
  end
end
