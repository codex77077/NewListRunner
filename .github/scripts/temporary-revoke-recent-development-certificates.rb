#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
require "time"
require "uri"

API_BASE = "https://api.appstoreconnect.apple.com"
DEVELOPMENT_TYPES = %w[DEVELOPMENT IOS_DEVELOPMENT MAC_APP_DEVELOPMENT].freeze

def required_env(name)
  value = ENV[name].to_s
  abort "缺少环境变量：#{name}" if value.empty?
  value
end

def encode(value)
  Base64.urlsafe_encode64(value, padding: false)
end

issuer_id = required_env("ASC_ISSUER_ID")
key_id = required_env("ASC_KEY_ID")
private_key = OpenSSL::PKey.read(required_env("ASC_PRIVATE_KEY"))
cutoff = Time.parse(required_env("CERTIFICATE_CUTOFF"))

p12 = OpenSSL::PKCS12.new(
  Base64.strict_decode64(required_env("APPLE_DISTRIBUTION_P12_BASE64").gsub(/\s+/, "")),
  required_env("APPLE_DISTRIBUTION_P12_PASSWORD")
)
protected_fingerprints = ([p12.certificate] + Array(p12.ca_certs)).compact.to_h do |certificate|
  [OpenSSL::Digest::SHA256.hexdigest(certificate.to_der), true]
end
abort "预置 P12 中未发现证书，拒绝执行撤销" if protected_fingerprints.empty?

now = Time.now.to_i
header = { alg: "ES256", kid: key_id, typ: "JWT" }
payload = { iss: issuer_id, iat: now - 5, exp: now + 600, aud: "appstoreconnect-v1" }
input = "#{encode(header.to_json)}.#{encode(payload.to_json)}"
der = private_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(input))
sequence = OpenSSL::ASN1.decode(der)
signature = sequence.value.map { |integer| [integer.value.to_s(16).rjust(64, "0")].pack("H*") }.join
token = "#{input}.#{encode(signature)}"

request = lambda do |method, path, expected|
  uri = path.start_with?("http") ? URI(path) : URI("#{API_BASE}#{path}")
  klass = { "GET" => Net::HTTP::Get, "DELETE" => Net::HTTP::Delete }.fetch(method)
  response = nil
  5.times do |attempt|
    http_request = klass.new(uri)
    http_request["Authorization"] = "Bearer #{token}"
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

list_certificates = lambda do
  items = []
  path = "/v1/certificates?limit=200"
  while path
    document = request.call("GET", path, [200])
    items.concat(document.fetch("data"))
    path = document.dig("links", "next")
  end
  items
end

certificate_for = lambda do |item|
  content = item.dig("attributes", "certificateContent")
  if content.to_s.empty?
    detail = request.call("GET", "/v1/certificates/#{item.fetch("id")}", [200]).fetch("data")
    content = detail.dig("attributes", "certificateContent")
  end
  abort "证书 #{item.fetch("id").to_s[-8, 8]} 缺少 certificateContent，拒绝继续" if content.to_s.empty?
  OpenSSL::X509::Certificate.new(Base64.strict_decode64(content.gsub(/\s+/, "")))
end

before = list_certificates.call
candidates = before.filter_map do |item|
  type = item.dig("attributes", "certificateType")
  next unless DEVELOPMENT_TYPES.include?(type)

  certificate = certificate_for.call(item)
  fingerprint = OpenSSL::Digest::SHA256.hexdigest(certificate.to_der)
  next if protected_fingerprints.key?(fingerprint)
  next if certificate.not_before < cutoff

  { item: item, certificate: certificate, type: type }
end

abort "候选证书超过 5 个，超出预期，拒绝批量撤销" if candidates.length > 5

puts "当前有效证书：#{before.length}；预置 P12 保护证书：#{protected_fingerprints.length}；待撤销近期开发证书：#{candidates.length}"
candidates.each_with_index do |candidate, index|
  certificate = candidate.fetch(:certificate)
  serial_suffix = certificate.serial.to_s(16).upcase[-8, 8]
  puts "候选 #{index + 1}：类型=#{candidate.fetch(:type)}，生效=#{certificate.not_before.utc.iso8601}，到期=#{certificate.not_after.utc.iso8601}，序列尾号=#{serial_suffix}"
end

candidates.each do |candidate|
  request.call("DELETE", "/v1/certificates/#{candidate.fetch(:item).fetch("id")}", [204])
end

remaining_ids = list_certificates.call.map { |item| item.fetch("id") }
not_removed = candidates.filter { |candidate| remaining_ids.include?(candidate.fetch(:item).fetch("id")) }
abort "仍有 #{not_removed.length} 个目标证书未撤销" unless not_removed.empty?

puts "撤销完成：#{candidates.length} 个；撤销后有效证书：#{remaining_ids.length}"
