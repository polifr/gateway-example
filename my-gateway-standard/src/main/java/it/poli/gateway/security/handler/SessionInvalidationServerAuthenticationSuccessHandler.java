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
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
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

    Mono<URI> logoutUri = clientRegistrationRepository
        .findByRegistrationId("keycloak-spring-gateway-client")
        .map((ClientRegistration clientRegistration) ->
            endSessionEndpoint(clientRegistration))
        .log();
//        .map(uri -> {
//          log.info("endSessionEndpoint: {}", uri.toString());
//          return uri;
//        }).log();

    // Ricerca e logout su Keycloak
    Mono<String> keycloakLogout = redisOperations.opsForHash().get(name, SESSION_ID_HASH_KEY)
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
            .map(p -> p.getIdToken().getTokenValue()))
            .log();
//            .map(t -> {
//              log.info("IdToken: {}", t);
//              return t;
//            });

    // Ricerca e cancellazione su Redis
    Mono<Void> oldReference = redisOperations.opsForHash().get(name, SESSION_ID_HASH_KEY)
        .map(Objects::toString)
        .log()
        .flatMap(sessionId -> redisOperations.delete(getSessionKey(sessionId)))
        .then();

    // Aggiunta del nuovo riferimento e impostazione durata nuovo riferimento
    Mono<Void> newReference = exchange.getSession().map(session -> session.getId())
        .log()
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
