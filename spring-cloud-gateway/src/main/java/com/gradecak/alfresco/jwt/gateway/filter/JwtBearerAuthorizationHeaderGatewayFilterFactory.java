package com.gradecak.alfresco.jwt.gateway.filter;

import java.nio.file.AccessDeniedException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import reactor.core.publisher.Mono;

public class JwtBearerAuthorizationHeaderGatewayFilterFactory
		extends AbstractGatewayFilterFactory<AbstractGatewayFilterFactory.NameConfig> {

	private final JWSSigner signer;

	public JwtBearerAuthorizationHeaderGatewayFilterFactory(JWSSigner signer) {
		super(NameConfig.class);

		this.signer = signer;
	}

	@Override
	public List<String> shortcutFieldOrder() {
		return Arrays.asList(NAME_KEY);
	}

	@Override
	public GatewayFilter apply(NameConfig config) {
		return (exchange, chain) -> ReactiveSecurityContextHolder.getContext().filter(Objects::nonNull)
				.map(securityContext -> securityContext.getAuthentication()).map(authentication -> {
					if (authentication instanceof OAuth2AuthenticationToken) {
						String token = createToken(signer, ((OAuth2AuthenticationToken) authentication).getName());
						return token;
					} else if (authentication instanceof UsernamePasswordAuthenticationToken) {
						String token = createToken(signer,
								((UsernamePasswordAuthenticationToken) authentication).getName());
						return token;
					}
					return null;
				}).filter(Objects::nonNull).switchIfEmpty(Mono.error(new AccessDeniedException("access denied")))
				.map(token -> {
					if (StringUtils.isEmpty(config.getName())) {
						final ServerHttpRequest request = exchange.getRequest().mutate()
								.headers(httpHeaders -> httpHeaders.setBearerAuth(token)).build();
						return exchange.mutate().request(request).build();
					}

					final ServerHttpRequest request = exchange.getRequest().mutate()
							.header(config.getName(), "Bearer " + token).build();
					return exchange.mutate().request(request).build();

				}).defaultIfEmpty(exchange).flatMap(chain::filter);
	}

	public static String createToken(JWSSigner signer, String username) {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(username)
				.claim("authorities", Collections.emptyList()).audience("gradecak").claim("username", username)
				.claim("typ", "Bearer").issuer("http://localhost:8180/auth/realms/alfresco")
				.claim("preferred_username", username).expirationTime(new Date(new Date().getTime() + 60 * 1000))
				.build();

		SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claimsSet);

		try {
			signedJWT.sign(signer);
			String token = signedJWT.serialize();

			return token;
		} catch (JOSEException e) {
			throw new RuntimeException("Token could not be created", e);
		}

	}
}
