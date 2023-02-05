package it.poli.gateway.security.handler;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import it.poli.gateway.security.exception.OidcAuthenticationException;
import reactor.core.publisher.Mono;

public class ReactiveOidcUserServiceFailureHandler implements ServerAuthenticationFailureHandler {

  private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

  private final RedirectServerLogoutSuccessHandler serverLogoutSuccessHandler =
      new RedirectServerLogoutSuccessHandler();

  private final ReactiveClientRegistrationRepository clientRegistrationRepository;

  private String postLogoutRedirectUri;

  public ReactiveOidcUserServiceFailureHandler(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
    this.clientRegistrationRepository = clientRegistrationRepository;
  }

  @Override
  public Mono<Void> onAuthenticationFailure(
      WebFilterExchange exchange, AuthenticationException exception) {

    return clientRegistrationRepository
        .findByRegistrationId("keycloak-spring-gateway-client")
        .flatMap(
            (ClientRegistration clientRegistration) -> {
              String idToken = null;
              if (exception instanceof OidcAuthenticationException) {
                idToken = ((OidcAuthenticationException) exception).getIdToken().getTokenValue();
              }

              URI endSessionEndpoint = endSessionEndpoint(clientRegistration);
              ServerHttpRequest request = exchange.getExchange().getRequest();
              String endpointUri =
                  endpointUri(
                      endSessionEndpoint,
                      "my-gateway",
                      idToken,
                      postLogoutRedirectUri(request));
              return Mono.just(endpointUri);
            })
        .switchIfEmpty(
            this.serverLogoutSuccessHandler.onLogoutSuccess(exchange, null).then(Mono.empty()))
        .flatMap(
            epUri -> this.redirectStrategy.sendRedirect(exchange.getExchange(), URI.create(epUri)));
  }

  private static URI endSessionEndpoint(ClientRegistration clientRegistration) {
    if (clientRegistration != null) {
      Object endSessionEndpoint =
          clientRegistration
              .getProviderDetails()
              .getConfigurationMetadata()
              .get("end_session_endpoint");
      if (endSessionEndpoint != null) {
        return URI.create(endSessionEndpoint.toString());
      }
    }
    return null;
  }

  private static String endpointUri(
      URI endSessionEndpoint, String clientId, String idToken, String postLogoutRedirectUri) {
    UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
    builder.queryParam("client_id", clientId);
    if (idToken != null) {
      builder.queryParam("id_token_hint", idToken);
    }
    if (postLogoutRedirectUri != null) {
      builder.queryParam("post_logout_redirect_uri", postLogoutRedirectUri);
    }
    return builder.encode(StandardCharsets.UTF_8).build().toUriString();
  }

  private String postLogoutRedirectUri(ServerHttpRequest request) {
    if (this.postLogoutRedirectUri == null) {
      return null;
    }

    UriComponents uriComponents =
        UriComponentsBuilder.fromUri(request.getURI())
            .replacePath(request.getPath().contextPath().value())
            .replaceQuery(null)
            .fragment(null)
            .build();
    return UriComponentsBuilder.fromUriString(this.postLogoutRedirectUri)
        .buildAndExpand(Collections.singletonMap("baseUrl", uriComponents.toUriString()))
        .toUriString();
  }

  public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
    Assert.notNull(postLogoutRedirectUri, "postLogoutRedirectUri cannot be null");
    this.postLogoutRedirectUri = postLogoutRedirectUri;
  }

  public void setLogoutSuccessUrl(URI logoutSuccessUrl) {
    Assert.notNull(logoutSuccessUrl, "logoutSuccessUrl cannot be null");
    this.serverLogoutSuccessHandler.setLogoutSuccessUrl(logoutSuccessUrl);
  }
}
