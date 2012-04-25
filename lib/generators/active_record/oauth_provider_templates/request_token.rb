class RequestToken < OauthToken

  attr_accessor :provided_oauth_verifier

  def authorize!(user)
    return false if authorized?
    self.user = user
    self.authorized_at = Time.now
    self.verifier=OAuth::Helper.generate_key(20)[0,20] unless oauth10?
    self.save
  end

  def exchange!
    return false unless authorized?
    return false unless oauth10? || verifier==provided_oauth_verifier

    RequestToken.transaction do
      access_token = AccessToken.create(:user => user, :client_application => client_application)
      invalidate!
      access_token
    end
  end

  def to_query
    if oauth10?
      super
    else
      "#{super}&oauth_callback_confirmed=true"
    end
  end

  def oob?
    callback_url.nil? || callback_url.downcase == 'oob'
  end

  def redirect_reqreuid?
    return true if client_application.oob?
    return true if callback_url.downcase == 'oob'
    client_application.callback_url.blank? &&  callback_url.blank?
  end

  def cancel_callback_url
    generate_callback_uri("failture=canceled")
  end

  def signin_callback_url
    generate_callback_uri("oauth_token=#{token}&oauth_verifier=#{verifier}")
  end

  def generate_callback_uri(query)
    url = callback_url.blank? ? client_application.callback_url : callback_url
    return if url.blank?
    uri = URI.parse(url.to_s)
    uri.query = uri.query.blank? ? query : "#{uri.query}&#{query}"
    uri.to_s
  end 


  def oauth10?
    (defined? OAUTH_10_SUPPORT) && OAUTH_10_SUPPORT && self.callback_url.blank?
  end

end
