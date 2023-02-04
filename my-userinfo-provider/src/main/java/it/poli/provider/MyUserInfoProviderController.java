package it.poli.provider;

import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class MyUserInfoProviderController {

  @GetMapping("/profile")
  @ResponseStatus(value = HttpStatus.OK)
  public Map<String, Object> profile(JwtAuthenticationToken token) {
    Jwt jwt = token.getToken();
    log.info("Jwt token: {}", jwt.getTokenValue());

    Map<String, Object> attrs = new HashMap<>(jwt.getClaims());
    log.info("Jwt claims attributes: {}", attrs);

    attrs.put("my_user_id", "12345");
    attrs.put("cms_roles", "101");

    return attrs;
  }

}
