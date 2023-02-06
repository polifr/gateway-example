package it.poli.gateway.router;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

@Configuration
public class StaticResourceConfiguration {

  @Bean
  RouterFunction<ServerResponse> staticResourceLocator() {
    return RouterFunctions.resources("/gw/**", new ClassPathResource("static/gw/"));
  }
}
