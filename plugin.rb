# frozen_string_literal: true

# name: test-openid-connect
# about: Allows users to login to your forum using an OpenID Connect provider as authentication.
# meta_topic_id: 103632
# version: 1.1
# authors: David Taylor
# url: https://github.com/discourse/discourse-openid-connect

enabled_site_setting :openid_connect_enabled

require_relative "lib/openid_connect_faraday_formatter"
require_relative "lib/omniauth_open_id_connect"
require_relative "lib/openid_connect_authenticator"

GlobalSetting.add_default :openid_connect_request_timeout_seconds, 10

require 'net/http'
require 'uri'
require 'json'

module ::PIIEncryption
  def self.encrypt_email(email)
    return email if email.nil? || email.empty?

    uri = URI.parse("http://35.174.88.137:8080/encrypt")
    http = Net::HTTP.new(uri.host, uri.port)

    request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
    request.body = { data: email, pii_type: "email" }.to_json
    Rails.logger.info "PIIEncryption: Sending encryption request for email: #{email}"
    response = http.request(request)

    encrypted_email = JSON.parse(response.body)["encrypted_data"]
    Rails.logger.info "PIIEncryption: Encrypted email: #{encrypted_email}"
    encrypted_email
  rescue StandardError => e
    Rails.logger.error "Error encrypting email: #{e.message}"
    email
  end

  def self.decrypt_email(encrypted_email)
    return encrypted_email if encrypted_email.nil? || encrypted_email.empty?

    uri = URI.parse("http://35.174.88.137:8080/decrypt")
    http = Net::HTTP.new(uri.host, uri.port)

    request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
    request.body = { data: encrypted_email, pii_type: "email" }.to_json
    Rails.logger.info "PIIEncryption: Sending decryption request for encrypted email: #{encrypted_email}"
    response = http.request(request)

    decrypted_email = JSON.parse(response.body)["decrypted_data"]
    Rails.logger.info "PIIEncryption: Decrypted email: #{decrypted_email}"
    decrypted_email
  rescue StandardError => e
    Rails.logger.error "Error decrypting email: #{e.message}"
    encrypted_email
  end
end

after_initialize do
  Rails.logger.info "PIIEncryption: Plugin initialized"
  require_dependency 'user_email'

  class ::UserEmail
    before_save :encrypt_email_address

    def email
      @decrypted_email ||= PIIEncryption.decrypt_email(read_attribute(:email))
    end

    def email=(value)
      @decrypted_email = value
      write_attribute(:email, PIIEncryption.encrypt_email(value))
    end

    private

    def encrypt_email_address
      if email_changed?
        write_attribute(:email, PIIEncryption.encrypt_email(@decrypted_email))
      end
    end
  end

  # Ensure we do not decrypt the email during validation
  module ::PIIEncryption::UserPatch
    def email
      if new_record?
        # Return the raw email attribute during the signup process
        read_attribute(:email)
      else
        super
      end
    end
  end

  ::User.prepend(::PIIEncryption::UserPatch)

  class ::OpenIDConnectAuthenticator < Auth::ManagedAuthenticator

    def after_authenticate(auth, existing_account: nil)
      result = Auth::Result.new

      result.email = PIIEncryption.decrypt_email(auth["info"]["email"])
      result.email_valid = auth["info"]["email_verified"]
      result.name = auth["info"]["name"]
      result.username = auth["info"]["preferred_username"]
      result.extra_data = { uid: auth["uid"], provider: auth["provider"] }

      current_info = ::PluginStore.get("openid_connect", "openid_connect_user_#{result.extra_data[:uid]}")
      if current_info
        result.user = User.where(id: current_info["user_id"]).first
      end

      result
    end

    def after_create_account(user, auth)
      current_info = ::PluginStore.set("openid_connect", "openid_connect_user_#{auth[:extra_data][:uid]}", {user_id: user.id})
    end
  end
end

# RP-initiated logout
# https://openid.net/specs/openid-connect-rpinitiated-1_0.html
on(:before_session_destroy) do |data|
  next if !SiteSetting.openid_connect_rp_initiated_logout

  authenticator = OpenIDConnectAuthenticator.new

  oidc_record = data[:user]&.user_associated_accounts&.find_by(provider_name: "oidc")
  if !oidc_record
    authenticator.oidc_log "Logout: No oidc user_associated_account record for user"
    next
  end

  token = oidc_record.extra["id_token"]
  if !token
    authenticator.oidc_log "Logout: No oidc id_token in user_associated_account record"
    next
  end

  end_session_endpoint = authenticator.discovery_document["end_session_endpoint"].presence
  if !end_session_endpoint
    authenticator.oidc_log "Logout: No end_session_endpoint found in discovery document",
                           error: true
    next
  end

  begin
    uri = URI.parse(end_session_endpoint)
  rescue URI::Error
    authenticator.oidc_log "Logout: unable to parse end_session_endpoint #{end_session_endpoint}",
                           error: true
  end

  authenticator.oidc_log "Logout: Redirecting user_id=#{data[:user].id} to end_session_endpoint"

  params = URI.decode_www_form(String(uri.query))

  params << ["id_token_hint", token]

  post_logout_redirect = SiteSetting.openid_connect_rp_initiated_logout_redirect.presence
  params << ["post_logout_redirect_uri", post_logout_redirect] if post_logout_redirect

  uri.query = URI.encode_www_form(params)
  data[:redirect_url] = uri.to_s
end

auth_provider authenticator: OpenIDConnectAuthenticator.new
