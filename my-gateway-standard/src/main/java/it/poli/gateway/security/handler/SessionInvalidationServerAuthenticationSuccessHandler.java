package it.poli.gateway.security.handler;

import java.time.Duration;
import java.util.Objects;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.session.data.redis.ReactiveRedisSessionRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class SessionInvalidationServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler{

  private final ReactiveRedisSessionRepository sessionRepository;
  private final ReactiveRedisOperations<String, Object> redisOperations;

  public SessionInvalidationServerAuthenticationSuccessHandler(
      ReactiveRedisSessionRepository sessionRepository) {
    super();
    this.sessionRepository = sessionRepository;
    this.redisOperations = sessionRepository.getSessionRedisOperations();
  }

  @Override
  public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange,
      Authentication authentication) {
    ServerWebExchange exchange = webFilterExchange.getExchange();
    String name = authentication.getName();

    // Ricerca e cancellazione
    Mono<Void> oldReference = redisOperations.opsForHash().get(name, "sessionId")
        .map(Objects::toString)
        .flatMap(sessionId -> sessionRepository.deleteById(sessionId))
        .then();

    // Aggiunta del nuovo riferimento e impostazione durata nuovo riferimento
    Mono<Void> newReference = exchange.getSession().map(session -> session.getId())
        .flatMap((String sessionId) -> {
          return redisOperations.opsForHash().put(name, "sessionId", sessionId)
              .and(redisOperations.expire(name, Duration.ofHours(12L)));
        }).then();

    return oldReference.and(newReference).then();
  }
}
