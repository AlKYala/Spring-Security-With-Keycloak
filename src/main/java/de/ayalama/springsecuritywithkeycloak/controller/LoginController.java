package de.ayalama.springsecuritywithkeycloak.controller;

import de.ayalama.springsecuritywithkeycloak.login.LoginResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@RestController
@RequestMapping("/login")
public class LoginController {

    @Autowired
    private Environment environment;


    @GetMapping("/blabla")
    public LoginResponse login(HttpServletRequest request) {


        String grant_type = request.getParameter("grant_type");
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String client_id = request.getParameter("client_id");

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", grant_type);
        map.add("username", username);
        map.add("password", password);
        map.add("client_id", client_id);

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);

        String postUrl = String.format("%s/protocol/openid-connect/token", environment.getProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri"));

        ResponseEntity<LoginResponse> response =
                restTemplate.exchange(postUrl,
                        HttpMethod.POST,
                        entity,
                        LoginResponse.class);

        //send x-www-form-urlencoded

        return response.getBody();
    }

}
