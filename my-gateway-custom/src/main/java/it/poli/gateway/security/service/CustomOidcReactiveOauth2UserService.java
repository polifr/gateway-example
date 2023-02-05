package it.poli.gateway.security.service;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import it.poli.gateway.security.exception.OidcAuthenticationException;
import reactor.core.publisher.Mono;

/**
 * Customizzazione della classe {@link OidcReactiveOAuth2UserService} per consentire l'inoltro del
 * token id nell'eccezione che e' sollevata in fase di estrazione delle informazioni utente.
 *
 * @author Francesco Poli
 */
public class CustomOidcReactiveOauth2UserService
    implements ReactiveOAuth2UserService<OidcUserRequest, OidcUser> {

  private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

  private static final Converter<Map<String, Object>, Map<String, Object>>
      DEFAULT_CLAIM_TYPE_CONVERTER = new ClaimTypeConverter(createDefaultClaimTypeConverters());

  private ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService =
      new DefaultReactiveOAuth2UserService();

  private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>>
      claimTypeConverterFactory = clientRegistration -> DEFAULT_CLAIM_TYPE_CONVERTER;

  /**
   * Creazione mappa dei converters necessari per l'estrazione dei valori dei claims.
   *
   * @return Mappa dei converters per l'estrazione dei valori dei claims
   */
  public static Map<String, Converter<Object, ?>> createDefaultClaimTypeConverters() {
    Converter<Object, ?> booleanConverter = getConverter(TypeDescriptor.valueOf(Boolean.class));
    Converter<Object, ?> instantConverter = getConverter(TypeDescriptor.valueOf(Instant.class));
    Map<String, Converter<Object, ?>> claimTypeConverters = new HashMap<>();
    claimTypeConverters.put(StandardClaimNames.EMAIL_VERIFIED, booleanConverter);
    claimTypeConverters.put(StandardClaimNames.PHONE_NUMBER_VERIFIED, booleanConverter);
    claimTypeConverters.put(StandardClaimNames.UPDATED_AT, instantConverter);
    return claimTypeConverters;
  }

  private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
    final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
    return source ->
        ClaimConversionService.getSharedInstance()
            .convert(source, sourceDescriptor, targetDescriptor);
  }

  /**
   * Restituisce un {@link OidcUser} dopo averne estratto gli attributi dall'url specificato come
   * UserInfo Endpoint nel ClientRegistration. Si differenzia dall'implementazione del {@link
   * ReactiveOAuth2UserService} per la diversa gestione delle eccezioni che si possono verificare in
   * fase di estrazione: se e' sollevata un'eccezione di tipo {@link OAuth2AuthenticationException}
   * allora viene convertita in {@link OidcAuthenticationException} in cui viene iniettato il valore
   * dell'idToken della userRequest, cosi' che possa essere usato per chiudere la sessione attiva
   * sul provider che ha fornito il token.
   *
   * @param userRequest La richiesta di informazioni dell'utente
   * @return L'oggetto {@link OidcUser} valorizzato
   * @throws OAuth2AuthenticationException se si verifica un errore mentre si procede all'estrazione
   *     delle informazioni dall'UserInfo Endpoint
   */
  @Override
  public Mono<OidcUser> loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
    Assert.notNull(userRequest, "userRequest cannot be null");
    return getUserInfo(userRequest)
        .onErrorMap(
            OAuth2AuthenticationException.class::isInstance,
            (Throwable ex) -> {
              throw new OidcAuthenticationException(
                  (OAuth2AuthenticationException) ex, userRequest.getIdToken());
            })
        .map(userInfo -> new OidcUserAuthority(userRequest.getIdToken(), userInfo))
        .defaultIfEmpty(new OidcUserAuthority(userRequest.getIdToken(), null))
        .map(
            (OidcUserAuthority authority) -> {
              OidcUserInfo userInfo = authority.getUserInfo();
              OAuth2AccessToken token = userRequest.getAccessToken();
              Set<GrantedAuthority> authorities = new HashSet<>(token.getScopes().size());
              authorities.add(authority);
              for (String scope : token.getScopes()) {
                authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
              }
              String userNameAttributeName =
                  userRequest
                      .getClientRegistration()
                      .getProviderDetails()
                      .getUserInfoEndpoint()
                      .getUserNameAttributeName();
              if (StringUtils.hasText(userNameAttributeName)) {
                return new DefaultOidcUser(
                    authorities, userRequest.getIdToken(), userInfo, userNameAttributeName);
              }
              return new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
            });
  }

  private Mono<OidcUserInfo> getUserInfo(OidcUserRequest userRequest) {
    if (!shouldRetrieveUserInfo(userRequest)) {
      return Mono.empty();
    }
    return this.oauth2UserService
        .loadUser(userRequest)
        .map(OAuth2User::getAttributes)
        .map(claims -> convertClaims(claims, userRequest.getClientRegistration()))
        .map(OidcUserInfo::new)
        .doOnNext(
            (OidcUserInfo userInfo) -> {
              String subject = userInfo.getSubject();
              if (subject == null || !subject.equals(userRequest.getIdToken().getSubject())) {
                OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
              }
            });
  }

  private Map<String, Object> convertClaims(
      Map<String, Object> claims, ClientRegistration clientRegistration) {
    Converter<Map<String, Object>, Map<String, Object>> claimTypeConverter =
        this.claimTypeConverterFactory.apply(clientRegistration);
    if (claimTypeConverter != null) {
      return claimTypeConverter.convert(claims);
    }
    return DEFAULT_CLAIM_TYPE_CONVERTER.convert(claims);
  }

  public void setOauth2UserService(
      ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
    Assert.notNull(oauth2UserService, "oauth2UserService cannot be null");
    this.oauth2UserService = oauth2UserService;
  }

  public final void setClaimTypeConverterFactory(
      Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>>
          claimTypeConverterFactory) {
    Assert.notNull(claimTypeConverterFactory, "claimTypeConverterFactory cannot be null");
    this.claimTypeConverterFactory = claimTypeConverterFactory;
  }

  static boolean shouldRetrieveUserInfo(OidcUserRequest userRequest) {
    ClientRegistration clientRegistration = userRequest.getClientRegistration();
    if (!StringUtils.hasText(
        clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())) {
      return false;
    }
    if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(
        clientRegistration.getAuthorizationGrantType())) {
      return CollectionUtils.containsAny(
          userRequest.getAccessToken().getScopes(),
          userRequest.getClientRegistration().getScopes());
    }
    return false;
  }
}
