package it.poli.gateway.security.exception;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

public class OidcAuthenticationException extends OAuth2AuthenticationException {

  private static final long serialVersionUID = 5132097796615075374L;

  private final OAuth2Error error;
  private final OidcIdToken idToken;

  public OidcAuthenticationException(
      OAuth2AuthenticationException oauth2AuthenticationException, OidcIdToken idToken) {
    super(oauth2AuthenticationException.getError(), oauth2AuthenticationException.getCause());
    this.error = oauth2AuthenticationException.getError();
    this.idToken = idToken;
  }

  public OidcIdToken getIdToken() {
    return idToken;
  }

  @Override
  public OAuth2Error getError() {
    return error;
  }
}
