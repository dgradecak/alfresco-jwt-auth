package com.gradecak.alfresco.jwt.gateway.filter;

import java.nio.file.AccessDeniedException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import reactor.core.publisher.Mono;

public class UsernameHeaderGatewayFilterFactory
		extends AbstractGatewayFilterFactory<AbstractGatewayFilterFactory.NameConfig> {

	public UsernameHeaderGatewayFilterFactory() {
		super(NameConfig.class);
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
						return ((OAuth2AuthenticationToken) authentication).getPrincipal().getName();
					} else if (authentication instanceof UsernamePasswordAuthenticationToken) {
						return ((User) authentication.getPrincipal()).getUsername();
					}
					return null;
				}).filter(Objects::nonNull).switchIfEmpty(Mono.error(new AccessDeniedException("access denied")))
				.map(email -> {
					final ServerHttpRequest request = exchange.getRequest().mutate().headers(httpHeaders -> {
						httpHeaders.set(config.getName(), email);
					}).build();
					return exchange.mutate().request(request).build();
				}).defaultIfEmpty(exchange).flatMap(chain::filter);
	}
}
