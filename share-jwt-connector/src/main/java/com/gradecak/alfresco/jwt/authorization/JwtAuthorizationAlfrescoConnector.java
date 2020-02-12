package com.gradecak.alfresco.jwt.authorization;

import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.alfresco.web.site.servlet.MTAuthenticationFilter;
import org.alfresco.web.site.servlet.SlingshotAlfrescoConnector;
import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorSession;
import org.springframework.extensions.webscripts.connector.RemoteClient;

public class JwtAuthorizationAlfrescoConnector extends SlingshotAlfrescoConnector {

	public static final String CS_PARAM_JWT = "jwtHeader";

	public JwtAuthorizationAlfrescoConnector(final ConnectorDescriptor descriptor, final String endpoint) {
		super(descriptor, endpoint);
	}

	@Override
	protected void applyRequestHeaders(final RemoteClient remoteClient, final ConnectorContext context) {

		super.applyRequestHeaders(remoteClient, context);
		
		HttpServletRequest req = ServletUtil.getRequest();
		if (req == null) {
			req = MTAuthenticationFilter.getCurrentServletRequest();
		}

		if (req != null) {
			String jwtHeader = connectorSession.getParameter(CS_PARAM_JWT);
			if (jwtHeader != null) {
				String token = req.getHeader(jwtHeader);
				remoteClient.setRequestProperties(Collections.singletonMap("Authorization", token));
			}
		}
	}

	private String getJwtHeader() {
		String jwtHeader = descriptor.getStringProperty(CS_PARAM_JWT);
		if (jwtHeader != null && jwtHeader.trim().length() == 0) {
			jwtHeader = null;
		}
		return jwtHeader;
	}

	@Override
	public void setConnectorSession(ConnectorSession connectorSession) {
		super.setConnectorSession(connectorSession);
		connectorSession.setParameter(CS_PARAM_JWT, getJwtHeader());
	}
}