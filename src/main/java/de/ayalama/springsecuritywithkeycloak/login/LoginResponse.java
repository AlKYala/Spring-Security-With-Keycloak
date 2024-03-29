package de.ayalama.springsecuritywithkeycloak.login;

import lombok.Data;

@Data
public class LoginResponse {

    private String access_token;
    private Integer expires_in;
    private Integer refresh_expires_in;
    private String refresh_token;
    private String token_type;
    private Integer notBeforePolicy;
    private String session_state;
    private String scope;
}
