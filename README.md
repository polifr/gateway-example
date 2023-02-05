# gateway-example

Examples for checking Spring Gateway behavior in managing sessions on user info requests error.

Repository contains the following modules:
- [my-container](https://github.com/polifr/gateway-example/tree/main/my-compose) contains a `docker-compose.yml` file that creates the services that are needed to support the gateway:
    - my-keycloak is a KeyCloak 19.0.3 instance that il configured to create a my-realm instance with a preconfigured user (username: `testuser`, password: `test`); it listens to the 8180 port.
    - my-redis is a Redis 7 instance used by the gateway to store session informations; it listens to the 6379 port.
    - my-nginx is a Nginx instance that holds a trivial `index.html` page with a welcome message and a logout button; it listens to he 8880 port (forwarded to the internal 80 by docker).
- [my-gateway-standard](https://github.com/polifr/gateway-example/tree/main/my-gateway-standard) is a Spring Boot 2.7.8 project that implements a Cloud Gateway configured to connect to the KeyCloak and the Redis instances running on docker, with routing strategy to the Nginx in case of successful login; this gateway instance is configured to use the Oauth2/Oidc security workflow for user authentication in the `SecurityConfiguration.java` class, as well as the logout strategy. The application listens to the 8080 port.
- [my-userinfo-provider](https://github.com/polifr/gateway-example/tree/main/my-userinfo-provider) is a Spring Boot 2.7.8 project that implements a microservice exposing the userinfo endpoint that is inquired by the gateway after a successful authentication on KeyCloak; it acts as a mock of a real service, since it only returns fixed values and it does not perform any query on databases, as it is done on a real case. The application listens to the 8081 port.
- [my-gateway-custom](https://github.com/polifr/gateway-example/tree/main/my-gateway-custom) is a gateway that is configured as the standard one, but contains the custom classes that I implemented to overcome the problems that I found on the userinfo request errors.

To use this example, you need to run first the `docker-compose up` command in the `my-compose` module; after that all the services have started, you can start the two Spring Boot projects (`my-gateway-standard` and `my-userinfo-provider`).

In the standard process, the user connects to the `http://localhost:8080` url, then is forwarded to the KeyCloak login page on `my-keycloak` service; if the credentias are valid, navigation is forwarded again on the gateway, that pulls the jwt token from KeyCloak, and then asks `my-userinfo-provider` for the attributes that need to be attached to the logged operator. Having done this, the request is forwarded to the `my-nginx` service that returns the `index.html` page.

The problem is when the communication between the gateway and the userinfo provider has some failure, or the provider returns an error (eg. the logged user is not found on the application domain); testing this behavior is simple using the example: you only need to shutdown the `my-userinfo-provider` application leaving the gateway and the other services running. In this situation, after the login on KeyCloak, the gateway forwards the navigation to a `/login?error` page, but this is a no-exit point. This happens because:
- The gateway uses `OidcReactiveOAuth2UserService` to extract the user informations, asking the `user-info-uri` supplied in the `application.yml` and forwarding the newly jwt token to the endpoint both for authentication and for user identification purposes. If the provider can't be reached, or returns an error value, the current `ServerAuthenticationFailureHandler` implementation manages the process and redirects the navigation to a specific page, by default `/login?error`. At this point, no `SecurityContext` nor `Authentication` instance is already created, so that user il logged on KeyCloak, but not on Spring Gateway.
- Once on the `/login?error` page, any try to return to the KeyCloak login fail, because there are still cookies connected to the KC domain that tell the server that the browser is already authenticated: this leads to turn back the navigation to the gateway, that gets the jwt token and so on, going back on the same error page if the userinfo provider returns the same response already given.

I tried to figure out how to make the sessions (Gateway and Keycloak) to be both closed after such an error, but the classes that are currently in the Spring Security packages seems to lack this option; in fact:
- I analyzed the `OidcClientInitiatedServerLogoutSuccessHandler` as a model to perform the shutdown of the KeyCloak session, but in that class the callback to the `end_session_endpoint` of the Oidc provider is called using the `Authentication` object that, as told before, is not present at this stage in the context.
- Moreover, the request to this `end_session_endpoint` must be done using the ID Token (not the full JWT one), that is quite forgotten by the process after the first call to the `user-info-uri`, and can't be recovered directly.

To overcome this, I tried to extend some classes to manage the specific error of the userinfo provider endpoint and the management of the KeyCloak session, that are shown in the `my-gateway-custom` project.

(TBD - description of custom project and logic)

