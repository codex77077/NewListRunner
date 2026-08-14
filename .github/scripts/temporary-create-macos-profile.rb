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
MAC_DISTRIBUTION_TYPES = %w[DISTRIBUTION IOS_DISTRIBUTION MAC_APP_DISTRIBUTION].freeze

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

protected_fingerprints = Tempfile.create(["distribution", ".p12"]) do |p12_file|
  p12_file.binmode
  p12_file.chmod(0o600)
  p12_file.write(Base64.strict_decode64(required_env("APPLE_DISTRIBUTION_P12_BASE64").gsub(/\s+/, "")))
  p12_file.flush

  Tempfile.create(["distribution-certificates", ".pem"]) do |certificate_file|
    certificate_file.chmod(0o600)
    _stdout, _stderr, status = Open3.capture3(
      { "P12_PASS" => required_env("APPLE_DISTRIBUTION_P12_PASSWORD") },
      "openssl", "pkcs12", "-legacy", "-in", p12_file.path, "-nokeys",
      "-passin", "env:P12_PASS", "-out", certificate_file.path
    )
    abort "无法解析预置 P12" unless status.success?
    certificate_file.rewind
    certificate_file.read.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).to_h do |pem|
      certificate = OpenSSL::X509::Certificate.new(pem)
      [OpenSSL::Digest::SHA256.hexdigest(certificate.to_der), true]
    end
  end
end
abort "预置 P12 中未发现证书" if protected_fingerprints.empty?

now = Time.now.to_i
header = { alg: "ES256", kid: key_id, typ: "JWT" }
payload = { iss: issuer_id, iat: now - 5, exp: now + 600, aud: "appstoreconnect-v1" }
input = "#{encode(header.to_json)}.#{encode(payload.to_json)}"
der = private_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(input))
sequence = OpenSSL::ASN1.decode(der)
signature = sequence.value.map { |integer| [integer.value.to_s(16).rjust(64, "0")].pack("H*") }.join
token = "#{input}.#{encode(signature)}"

request = lambda do |method, path, body, expected|
  uri = path.start_with?("http") ? URI(path) : URI("#{API_BASE}#{path}")
  klass = { "GET" => Net::HTTP::Get, "POST" => Net::HTTP::Post }.fetch(method)
  response = nil
  5.times do |attempt|
    http_request = klass.new(uri)
    http_request["Authorization"] = "Bearer #{token}"
    if body
      http_request["Content-Type"] = "application/json"
      http_request.body = JSON.generate(body)
    end
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 30, read_timeout: 120) do |http|
      http.request(http_request)
    end
    break unless response.code.to_i == 429 || response.code.to_i >= 500
    sleep([2**attempt, 16].min)
  end
  status = response.code.to_i
  return response.body.to_s.empty? ? {} : JSON.parse(response.body) if expected.include?(status)

  details = begin
    JSON.parse(response.body.to_s).fetch("errors", []).map { |error| error["detail"] || error["title"] }.join(" | ")
  rescue JSON::ParserError
    "响应不是 JSON"
  end
  abort "App Store Connect #{method} #{uri.path} 失败（HTTP #{status}）：#{details}"
end

list = lambda do |path|
  items = []
  while path
    document = request.call("GET", path, nil, [200])
    items.concat(document.fetch("data"))
    path = document.dig("links", "next")
  end
  items
end

certificates = list.call("/v1/certificates?limit=200")
matching_certificates = certificates.filter do |item|
  type = item.dig("attributes", "certificateType")
  next false unless MAC_DISTRIBUTION_TYPES.include?(type)
  content = item.dig("attributes", "certificateContent")
  if content.to_s.empty?
    content = request.call("GET", "/v1/certificates/#{item.fetch("id")}", nil, [200]).dig("data", "attributes", "certificateContent")
  end
  next false if content.to_s.empty?
  certificate = OpenSSL::X509::Certificate.new(Base64.strict_decode64(content.gsub(/\s+/, "")))
  protected_fingerprints.key?(OpenSSL::Digest::SHA256.hexdigest(certificate.to_der))
end
abort "Apple 账户中未找到与预置 P12 完全匹配的 distribution 证书" if matching_certificates.empty?
abort "Apple 账户中有多个证书与预置 P12 匹配，拒绝猜测" unless matching_certificates.length == 1
certificate = matching_certificates.fetch(0)

query = URI.encode_www_form("filter[identifier]" => "com.gendago.alist", "limit" => 200)
bundle_ids = list.call("/v1/bundleIds?#{query}").filter do |item|
  item.dig("attributes", "identifier") == "com.gendago.alist" &&
    %w[MAC_OS UNIVERSAL].include?(item.dig("attributes", "platform"))
end
abort "未找到 com.gendago.alist 的 macOS/Universal Bundle ID" if bundle_ids.empty?
abort "找到多个可用于 macOS 的同名 Bundle ID，拒绝猜测" unless bundle_ids.length == 1
bundle_id = bundle_ids.fetch(0)

profile_name = "NewList macOS CI Manual #{Time.now.utc.strftime('%Y%m%d%H%M%S')}"
profile = request.call("POST", "/v1/profiles", {
  data: {
    type: "profiles",
    attributes: { name: profile_name, profileType: "MAC_APP_STORE" },
    relationships: {
      bundleId: { data: { type: "bundleIds", id: bundle_id.fetch("id") } },
      certificates: { data: [{ type: "certificates", id: certificate.fetch("id") }] }
    }
  }
}, [201]).fetch("data")

profile_content = profile.dig("attributes", "profileContent")
abort "新 profile 缺少 profileContent" if profile_content.to_s.empty?
plain_profile = Base64.strict_decode64(profile_content.gsub(/\s+/, ""))
abort "新 profile 内容为空" if plain_profile.empty?

key = Base64.strict_decode64(required_env("B3"))
abort "B3 长度错误" unless key.bytesize == 32
magic = "S1\x00\x01".b
cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
cipher.key = key
nonce = OpenSSL::Random.random_bytes(12)
cipher.iv = nonce
cipher.auth_data = magic
ciphertext = cipher.update(plain_profile) + cipher.final
sealed = magic + nonce + ciphertext + cipher.auth_tag
File.binwrite(output_path, sealed, mode: "w", perm: 0o600)

puts "已基于预置证书创建 profile：类型=#{profile.dig("attributes", "profileType")}，平台=#{profile.dig("attributes", "platform")}，到期=#{profile.dig("attributes", "expirationDate")}"
