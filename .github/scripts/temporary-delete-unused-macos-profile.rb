#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
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

issuer_id = required_env("ASC_ISSUER_ID")
key_id = required_env("ASC_KEY_ID")
private_key = OpenSSL::PKey.read(required_env("ASC_PRIVATE_KEY"))
expected_name = required_env("PROFILE_NAME")
expected_uuid = required_env("PROFILE_UUID")

now = Time.now.to_i
header = { alg: "ES256", kid: key_id, typ: "JWT" }
payload = { iss: issuer_id, iat: now - 5, exp: now + 600, aud: "appstoreconnect-v1" }
input = "#{encode(header.to_json)}.#{encode(payload.to_json)}"
der = private_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(input))
sequence = OpenSSL::ASN1.decode(der)
signature = sequence.value.map { |integer| [integer.value.to_s(16).rjust(64, "0")].pack("H*") }.join
token = "#{input}.#{encode(signature)}"

request = lambda do |method, path, expected|
  uri = URI("#{API_BASE}#{path}")
  klass = { "GET" => Net::HTTP::Get, "DELETE" => Net::HTTP::Delete }.fetch(method)
  http_request = klass.new(uri)
  http_request["Authorization"] = "Bearer #{token}"
  response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 30, read_timeout: 120) do |http|
    http.request(http_request)
  end
  status = response.code.to_i
  return response.body.to_s.empty? ? {} : JSON.parse(response.body) if expected.include?(status)

  details = begin
    JSON.parse(response.body.to_s).fetch("errors", []).map { |error| error["detail"] || error["title"] }.join(" | ")
  rescue JSON::ParserError
    "响应不是 JSON"
  end
  abort "App Store Connect #{method} 失败（HTTP #{status}）：#{details}"
end

query = URI.encode_www_form("filter[name]" => expected_name, "limit" => 200)
profiles = request.call("GET", "/v1/profiles?#{query}", [200]).fetch("data").filter do |item|
  item.dig("attributes", "name") == expected_name
end
abort "未找到待清理 profile" if profiles.empty?
abort "同名 profile 超过一个，拒绝猜测" unless profiles.length == 1
profile = profiles.fetch(0)
attributes = profile.fetch("attributes")
abort "profile UUID 不匹配，拒绝删除" unless attributes["uuid"] == expected_uuid
abort "profile 类型不匹配，拒绝删除" unless attributes["profileType"] == "MAC_APP_STORE"
abort "profile 平台不匹配，拒绝删除" unless attributes["platform"] == "MAC_OS"

request.call("DELETE", "/v1/profiles/#{profile.fetch("id")}", [204])
remaining = request.call("GET", "/v1/profiles?#{query}", [200]).fetch("data").any? do |item|
  item.dig("attributes", "uuid") == expected_uuid
end
abort "profile 删除后仍可查询到" if remaining

puts "未使用的临时 macOS profile 已按名称、UUID、类型和平台精确删除"
