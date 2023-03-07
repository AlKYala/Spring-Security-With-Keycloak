package de.ayalama.springsecuritywithkeycloak.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@Slf4j
public class KeycloakLogoutHandler implements LogoutHandler {

    private final RestTemplate restTemplate;

    public KeycloakLogoutHandler() {
        this.restTemplate = new RestTemplate(); //ich hab hier keine textra defintion eines RestTemplate als Bean, Component oder sonst wie - daher sollte die standard sache reichen.
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
                       Authentication auth) {
        logoutFromKeycloak((OidcUser) auth.getPrincipal());
    }

    private void logoutFromKeycloak(OidcUser oidcUser) {
        String endSessionEndpoint = String.format("%s/protocol/openid-connect/logout", oidcUser.getIssuer());

        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(endSessionEndpoint)
                .queryParam("id_token_hint", oidcUser.getIdToken().getTokenValue()); //wir setzen hier nur nen param

        //wir senden also einen request an die Keycloak API um uns auszuloggen.
        ResponseEntity<String> logoutResponse = restTemplate.getForEntity(
                builder.toUriString(), String.class);

        if(logoutResponse.getStatusCode().is2xxSuccessful()) {
            log.info("Logout Successful");
        }
        else {
            log.error("logout not successful");
        }
    }

}
