package com.spring.boot.security;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

	KeyPair keyPair;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private Environment environment;
	
	public void configure(AuthorizationServerSecurityConfigurer security) {
		security.tokenKeyAccess("permitAll()")
		.checkTokenAccess("isAuthenticated");
	}
	
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory().withClient("clientuser")
		.secret(passwordEncoder.encode("clientsecret"))
		.authorizedGrantTypes("client_credentials")
		.scopes("resource-server-read", "resource-server-write");
	}
	
	public void configure(AuthorizationServerEndpointsConfigurer endPoints) {
		endPoints.accessTokenConverter(accessTokenConverter())
		.tokenStore(tokenStore());
	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setSigningKey("123");
		return converter;
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		String idForEncode = "bycrpt";
		Map<String, PasswordEncoder> encoderMap = new HashMap<>();
		encoderMap.put(idForEncode, new BCryptPasswordEncoder());
		return new DelegatingPasswordEncoder(idForEncode, encoderMap);
	}
}
