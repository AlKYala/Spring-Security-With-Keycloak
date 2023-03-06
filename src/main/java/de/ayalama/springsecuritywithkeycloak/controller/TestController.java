package de.ayalama.springsecuritywithkeycloak.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/customers")
    public String customerPath() {
        return "Users and Customers can access this";
    }

    @GetMapping("/all")
    public String allPath() {
        return "everyone can access this";
    }
}
