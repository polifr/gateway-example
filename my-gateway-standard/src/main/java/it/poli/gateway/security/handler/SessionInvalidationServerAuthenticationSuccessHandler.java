package it.poli.gateway.security.handler;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.session.data.redis.ReactiveRedisSessionRepository;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

public class SessionInvalidationServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler{

  private static final String SESSION_ID_HASH_KEY = "sessionId";

  private final ReactiveClientRegistrationRepository clientRegistrationRepository;
  private final ReactiveRedisOperations<String, Object> redisOperations;

  public SessionInvalidationServerAuthenticationSuccessHandler(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ReactiveRedisSessionRepository sessionRepository) {
    super();
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.redisOperations = sessionRepository.getSessionRedisOperations();
  }

  @Override
  public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange,
      Authentication authentication) {
    ServerWebExchange exchange = webFilterExchange.getExchange();
    String name = authentication.getName();

    // Url base di logout su Keycloak
    Mono<URI> logoutUri = clientRegistrationRepository
        .findByRegistrationId("keycloak-spring-gateway-client")
        .map((ClientRegistration clientRegistration) ->
            endSessionEndpoint(clientRegistration));

    // IdToken da inviare a Keycloak per logout
    Mono<String> idToken = redisOperations.opsForHash().get(name, SESSION_ID_HASH_KEY)
        .map(Objects::toString)
        .flatMap(sessionId -> redisOperations.opsForHash()
            .get(getSessionKey(sessionId), "sessionAttr:SPRING_SECURITY_CONTEXT")
            .filter(SecurityContext.class::isInstance)
            .cast(SecurityContext.class)
            .map(securityContext -> securityContext.getAuthentication())
            .filter(OAuth2AuthenticationToken.class::isInstance)
            .filter((token) -> authentication.getPrincipal() instanceof OidcUser)
            .map(OAuth2AuthenticationToken.class::cast)
            .map(auth -> auth.getPrincipal())
            .cast(OidcUser.class)
            .map(p -> p.getIdToken().getTokenValue()));

    // Url di logout su keycloak
    Mono<Void> keycloakLogout = Mono.zip(logoutUri, idToken)
        .map(tuple -> endpointUri(tuple.getT1(), tuple.getT2()))
        .flatMap(SessionInvalidationServerAuthenticationSuccessHandler::callEndSessionEndpoint)
        .then();

    // Ricerca e cancellazione su Redis
    Mono<Void> oldReference = redisOperations.opsForHash().get(name, SESSION_ID_HASH_KEY)
        .map(Objects::toString)
        .flatMap(sessionId -> redisOperations.delete(getSessionKey(sessionId)))
        .then();

    // Aggiunta del nuovo riferimento e impostazione durata nuovo riferimento
    Mono<Void> newReference = exchange.getSession().map(session -> session.getId())
        .flatMap((String sessionId) -> {
          return redisOperations.opsForHash().put(name, SESSION_ID_HASH_KEY, sessionId)
              .and(redisOperations.expire(name, Duration.ofHours(12L)));
        }).then();

    return logoutUri.and(keycloakLogout).and(oldReference).then(newReference).then();
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

  private static String endpointUri(URI endSessionEndpoint, String idToken) {
    UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
    builder.queryParam("client_id", "my-gateway");
    builder.queryParam("id_token_hint", idToken);
    return builder.encode(StandardCharsets.UTF_8).build().toUriString();
  }

  private static Mono<Void> callEndSessionEndpoint(String endpointUri) {
    return WebClient.builder().baseUrl(endpointUri).build()
        .get().retrieve().toBodilessEntity().then();
  }

  private String getSessionKey(String sessionId) {
    return "my-gateway-standard:session:sessions:" + sessionId;
  }
}
