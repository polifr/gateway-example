package it.poli.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.DelegatingServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.session.data.redis.ReactiveRedisSessionRepository;
import it.poli.gateway.security.handler.SessionInvalidationServerAuthenticationSuccessHandler;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

  @Bean
  ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
    return new WebSessionServerOAuth2AuthorizedClientRepository();
  }

  @Bean
  SecurityWebFilterChain springSecurityFilterChain(
      ServerHttpSecurity http, 
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ReactiveRedisSessionRepository sessionRepository) {

    http.formLogin().disable();
    http.httpBasic().disable();

    // Disabled only in this example; in the real gateway is enabled and managed by XSRF tokens / cookies
    http.csrf().disable();

    http.authorizeExchange().anyExchange().authenticated();
    http.oauth2Login(
        login -> login.authenticationSuccessHandler(
            authenticationSuccessHandler(clientRegistrationRepository, sessionRepository)));
    http.logout(
        logout ->
            logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)));

    return http.build();
  }

  private static ServerAuthenticationSuccessHandler authenticationSuccessHandler(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ReactiveRedisSessionRepository sessionRepository) {
    SessionInvalidationServerAuthenticationSuccessHandler sessionInvalidationHanlder =
        new SessionInvalidationServerAuthenticationSuccessHandler(
            clientRegistrationRepository, sessionRepository);
    RedirectServerAuthenticationSuccessHandler redirectHandler =
        new RedirectServerAuthenticationSuccessHandler();
    DelegatingServerAuthenticationSuccessHandler delegatingHandler =
        new DelegatingServerAuthenticationSuccessHandler(sessionInvalidationHanlder,
            redirectHandler);
    return delegatingHandler;
  }

  private static ServerLogoutSuccessHandler oidcLogoutSuccessHandler(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    OidcClientInitiatedServerLogoutSuccessHandler logoutSuccessHandler =
        new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
    logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
    return logoutSuccessHandler;
  }
}
