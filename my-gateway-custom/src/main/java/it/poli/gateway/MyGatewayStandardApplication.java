package it.poli.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = ReactiveUserDetailsServiceAutoConfiguration.class)
public class MyGatewayStandardApplication {

  public static void main(String[] args) {
    SpringApplication.run(MyGatewayStandardApplication.class, args);
  }

}
