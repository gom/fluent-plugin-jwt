module Fluent
  module Plugin
    module JwtPluginUtil
      def key_file(path, key_algorithm)
        file = File.new path

        case key_algorithm.to_s
        when "rsa"; OpenSSL::PKey::RSA.new file
        when "ecdsa"; OpenSSL::PKey::EC.new file
        else raise Fluent::ConfigError, "Unsupported key_algorithm"
        end
      end
    end
  end
end
