#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "open3"
require "openssl"
require "tempfile"
require "time"
require "uri"

API_BASE = "https://api.appstoreconnect.apple.com"

def required_env(name)
  value = ENV[name].to_s
  abort "缺少环境变量：#{name}" if value.empty?
  value
end

def encode(value)
  Base64.urlsafe_encode64(value, padding: false)
end

output_path = ARGV.fetch(0)
issuer_id = required_env("ASC_ISSUER_ID")
key_id = required_env("ASC_KEY_ID")
private_key = OpenSSL::PKey.read(required_env("ASC_PRIVATE_KEY"))

now = Time.now.to_i
header = { alg: "ES256", kid: key_id, typ: "JWT" }
payload = { iss: issuer_id, iat: now - 5, exp: now + 600, aud: "appstoreconnect-v1" }
input = "#{encode(header.to_json)}.#{encode(payload.to_json)}"
der = private_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(input))
sequence = OpenSSL::ASN1.decode(der)
signature = sequence.value.map { |integer| [integer.value.to_s(16).rjust(64, "0")].pack("H*") }.join
token = "#{input}.#{encode(signature)}"

rsa_key = OpenSSL::PKey::RSA.new(2048)
csr = OpenSSL::X509::Request.new
csr.version = 0
csr.subject = OpenSSL::X509::Name.parse("/CN=NewList CI Mac Installer")
csr.public_key = rsa_key.public_key
csr.sign(rsa_key, OpenSSL::Digest::SHA256.new)

uri = URI("#{API_BASE}/v1/certificates")
request = Net::HTTP::Post.new(uri)
request["Authorization"] = "Bearer #{token}"
request["Content-Type"] = "application/json"
request.body = JSON.generate({
  data: {
    type: "certificates",
    attributes: {
      certificateType: "MAC_INSTALLER_DISTRIBUTION",
      csrContent: csr.to_pem
    }
  }
})
response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 30, read_timeout: 120) do |http|
  http.request(request)
end
unless response.code.to_i == 201
  details = begin
    JSON.parse(response.body.to_s).fetch("errors", []).map { |error| error["detail"] || error["title"] }.join(" | ")
  rescue JSON::ParserError
    "响应不是 JSON"
  end
  abort "创建 Mac Installer Distribution 证书失败（HTTP #{response.code}）：#{details}"
end

certificate_data = JSON.parse(response.body).fetch("data")
certificate_type = certificate_data.dig("attributes", "certificateType")
abort "Apple 返回了错误的证书类型：#{certificate_type}" unless certificate_type == "MAC_INSTALLER_DISTRIBUTION"
certificate_content = certificate_data.dig("attributes", "certificateContent")
abort "Apple 返回的证书内容为空" if certificate_content.to_s.empty?
certificate = OpenSSL::X509::Certificate.new(Base64.strict_decode64(certificate_content.gsub(/\s+/, "")))
abort "返回证书与本次私钥不匹配" unless certificate.public_key.to_der == rsa_key.public_key.to_der

p12_password = Base64.strict_encode64(OpenSSL::Random.random_bytes(36))
p12_bytes = Tempfile.create(["mac-installer", ".key"]) do |key_file|
  key_file.chmod(0o600)
  key_file.write(rsa_key.to_pem)
  key_file.flush
  Tempfile.create(["mac-installer", ".pem"]) do |certificate_file|
    certificate_file.chmod(0o600)
    certificate_file.write(certificate.to_pem)
    certificate_file.flush
    Tempfile.create(["mac-installer", ".p12"]) do |p12_file|
      p12_file.chmod(0o600)
      _stdout, _stderr, status = Open3.capture3(
        { "P12_PASS" => p12_password },
        "openssl", "pkcs12", "-export", "-legacy", "-inkey", key_file.path,
        "-in", certificate_file.path, "-name", "Mac Installer Distribution",
        "-passout", "env:P12_PASS", "-out", p12_file.path
      )
      abort "无法封装 Mac Installer Distribution P12" unless status.success?
      File.binread(p12_file.path)
    end
  end
end

envelope = JSON.generate({
  "p12_base64" => Base64.strict_encode64(p12_bytes),
  "password" => p12_password,
  "certificate_type" => certificate_type,
  "expiration_date" => certificate_data.dig("attributes", "expirationDate")
})
key = Base64.strict_decode64(required_env("B3"))
abort "B3 长度错误" unless key.bytesize == 32
magic = "S1\x00\x01".b
cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
cipher.key = key
nonce = OpenSSL::Random.random_bytes(12)
cipher.iv = nonce
cipher.auth_data = magic
ciphertext = cipher.update(envelope) + cipher.final
File.binwrite(output_path, magic + nonce + ciphertext + cipher.auth_tag, mode: "w", perm: 0o600)

puts "已创建并封装固定证书：类型=#{certificate_type}，到期=#{certificate_data.dig("attributes", "expirationDate")}"
