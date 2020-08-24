package com.spring.boot;

import java.security.Principal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@EnableResourceServer
@SpringBootApplication(scanBasePackages={"com.spring"})
public class AuthorizationServerApp {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerApp.class, args);
	}
	
	@GetMapping("/validateUser")
	public Principal user(Principal user) {
		return user;
	}
}
