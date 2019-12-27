require "fluent/plugin/filter"
require "fluent/plugin/jwt_plugin_util"
require 'json/jwt'

require "net/http"
require "uri"

module Fluent
  module Plugin
    class JwtDecodeFilter < Fluent::Plugin::Filter
      include JwtPluginUtil

      Fluent::Plugin.register_filter("jwt_decode", self)

      config_param :public_key_file, :string, :default => "pub.pem"
      config_param :key_algorithm, :enum, list: [:ecdsa, :rsa], default: :ecdsa
      config_param :jwk_set_url, :string, :default => nil

      config_param :key, :string
      config_param :remove_key, :bool, :default => false
      config_param :target_key, :string

      desc "ID Token verifier settings"
      config_section :verify, multi: true do
        config_param :iss, :string, :default => nil
        config_param :iss_key, :string, :default => nil
        config_param :aud, :string, :default => nil
        config_param :aud_key, :string, :default => nil
        config_param :ignore_nonce, :bool, :default => false
        config_param :nonce, :string, :default => nil
        config_param :nonce_key, :string, :default => nil
      end

      def jwk_set(jku)
        begin
          JSON::JWK::Set.new(JSON.parse(Net::HTTP.get(URI.parse(jku))))
        rescue JSON::ParserError => e
          log.error "JSON Web Key parse error", error: e.to_s
          log.debug_backtrace(e.backtrace)
        end
      end

      def configure(conf)
        super
          @jwk_pub = if @jwk_set_url
            jwk_set(@jwk_set_url)
          elsif @public_key_file
            key_file(@public_key_file, @key_algorithm).to_jwk
          else
            raise Fluent::ConfigError, "jwk_set_url or public_key_file is required"
          end
      end

      def filter(tag, time, record)
        unless record[@key]
          log.info "#{@key} doesn't included: #{record.to_s}"
          return record
        end

        payload = JSON::JWT.decode record[@key], @jwk_pub
        log.debug payload.to_s
        # TODO: use optional headers: jwk, jku
        
        unless @verify.empty? || verify_signature(record, payload)
          log.error "ID Token Verification Failed! token_string: #{record[@key]} payload: #{payload}"
          return record
        end

        record[@target_key] = payload
        record.remove(@key) if @remove_key

        record
      end

      def verify_signature(record, payload)
        @verify.any? do |verify|
          expected_iss = if verify.iss
            verify.iss
          elsif verify.iss_key && record[verify.iss_key]
            record[verify.iss_key]
          end

          expected_aud = if verify.aud
            verify.aud
          elsif verify.aud_key && record[verify.aud_key]
            record[verify.aud_key]
          end

          expected_nonce = if verify.nonce
            verify.nonce
          elsif verify.nonce_key && record[verify.nonce_key]
            record[verify.nonce_key]
          end

          (
            payload[:iss] == expected_iss &&
            payload[:aud] == expected_aud &&
            payload[:sub].present? &&
            Time.at(payload[:exp]) > Time.now &&
            (!verify.ignore_nonce && payload[:nonce] == expected_nonce)
          )
        end
      end
    end
  end
end
