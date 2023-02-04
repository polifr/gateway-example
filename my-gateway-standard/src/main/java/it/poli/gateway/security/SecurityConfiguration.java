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
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

  @Bean
  ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
    return new WebSessionServerOAuth2AuthorizedClientRepository();
  }

  @Bean
  SecurityWebFilterChain springSecurityFilterChain(
      ServerHttpSecurity http, ReactiveClientRegistrationRepository clientRegistrationRepository) {

    http.formLogin().disable();
    http.httpBasic().disable();

    // Disabled only in this example; in the real gateway is enabled and managed by XSRF tokens / cookies
    http.csrf().disable();

    http.authorizeExchange().anyExchange().authenticated();
    http.oauth2Login();
    http.logout(
        logout ->
            logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)));

    return http.build();
  }

  private static ServerLogoutSuccessHandler oidcLogoutSuccessHandler(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    OidcClientInitiatedServerLogoutSuccessHandler logoutSuccessHandler =
        new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
    logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
    return logoutSuccessHandler;
  }
}
