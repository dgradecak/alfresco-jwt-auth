package com.gradecak.alfresco.jwt.gateway;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;

import com.gradecak.alfresco.jwt.gateway.filter.JwtBearerAuthorizationHeaderGatewayFilterFactory;
import com.gradecak.alfresco.jwt.gateway.filter.UsernameHeaderGatewayFilterFactory;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;

import de.codecentric.boot.admin.server.config.EnableAdminServer;

@Configuration
@EnableAutoConfiguration
@EnableAdminServer
@EnableWebFluxSecurity
public class CloudGatewayConfiguration {

	private Resource resource = new ClassPathResource("/mytest.jks");
	private String alias = "mytest";
	private String password = "mypass";

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange().pathMatchers("/login/**", "/favicon.ico", "/css/**", "/image/**").permitAll().and()
				.authorizeExchange().pathMatchers("/admin/**").hasRole("ADMINISTRATOR").anyExchange().authenticated().and().formLogin().and().httpBasic().and()
				.oauth2Login().and().cors().disable().csrf().disable().headers()
				.referrerPolicy(ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE);
		return http.build();
	}

	@Bean
	public JWSSigner jwsSigner() {
		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(resource, password.toCharArray());

		return new RSASSASigner(keyStoreKeyFactory.getKeyPair(alias).getPrivate());
	}

	@Bean
	public UsernameHeaderGatewayFilterFactory usernameHeaderGatewayFilterFactory() {
		return new UsernameHeaderGatewayFilterFactory();
	}

	@Bean
	public JwtBearerAuthorizationHeaderGatewayFilterFactory jwtHeaderGatewayFilterFactory(JWSSigner jws) {
		return new JwtBearerAuthorizationHeaderGatewayFilterFactory(jws);
	}
}
