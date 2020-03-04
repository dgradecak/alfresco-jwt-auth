
Spring Cloud Gateway for the Alfresco platform
===
Enables OAuth2 for Alfresco and works on Enterprise as well as on Community. With this approach, ACS becomes a resource server.

![Login form](/images/screenshots/login.png)
*Login with local user or OAuth2*

[Spring Cloud Gateway](https://spring.io/projects/spring-cloud-gateway)

[Spring Boot Admin Server](https://github.com/codecentric/spring-boot-admin) is enabled and accessible at http://localhost:9595/admin

The gateway is used instead of a proxy (such as Nginx or Apache Httpd) and all the trafic should be routed through it. It will add the required headers to the request
and will send them to Alfresco Share which in its turn will send the received JWT to Alfresco content services.

Spring Cloud Gateway is based on WebFlux and the reactor project and provides simple integrations with OAuth2 providers such as Google, Facebook, Github, Okta ...

- manual configuration and install
- TODO docker setup

Alfresco Share
-
Share does not support Alfresco Identity Services but with a mimal customization we can enable JWT support in Alfresco Share.
* checkout the sub-project share-jwt-connector and build the jar which you need to provide inside of your Share installation
`mvn clean package`
* TODO maven-central

You will have to configure Share for External Authentication (please follow [Alfresco External Authentication](https://docs.alfresco.com/6.2/tasks/auth-alfrescoexternal-sso.html)). Once done just change the connector with ID "alfrescoHeader" with the following configuration

         <connector>
            <id>alfrescoHeader</id>
            <name>Alfresco Connector</name>
            <description>Connects to an Alfresco instance using header and cookie-based authentication</description>
            <class>com.gradecak.alfresco.share.authorization.JwtAuthorizationAlfrescoConnector</class>
            <userHeader>X-Alfresco-Remote-User</userHeader>
            <jwtHeader>WEB_TOKEN</jwtHeader>
         </connector>

if you prefer just using Alfresco External Authentication, without Alfresco Identity Services than you do not need to add the customized configuration above, just use the one provided by Alfresco.

You might experience a redirect loop when using Share through the gateway, this is mainly caused if you login/logout in the same browser session. I recommend that you use an "incognito" browsing mode for each new session, simply to avoid this issue during development.

Alfresco Content Services config
-
there is no customization needed on the repository side, since here we reuse the Alfresco Identity Service (aka Keycloack) authentication configuration. However we do not need any instance of AIS or Keyloack since the JWT is created and signed by the Spring Cloud Gateway/Spring Security integration.

In order to configure you will need to enable Alfresco identity service authentication (the most common way is via alfresco-global.properties)
* identity-service.authentication.enabled=true
* identity-service.authentication.enable-username-password-authentication=false
* identity-service.bearer-only=true
* identity-service.realm-public-key=YOUR_PUBLIC_KEY

the public key used in the sample is => `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsR2E4gZpYgv3tw6KDf6Ms89W/1/UKQY5uQTcPGwUMJkbRgW0ovO9nxQiOmxPr/gs0dS9DVnpbPh9SuDuRDEDrFdyvrkU+4SHAJYoh82OjLrBhnEH9pC/OEG/vxHUCv0qBbIeaoNaTittnHW4YcTKxchVCJM4F0L4tsP6B8kKMaOyTVE9Q2tJu5ipiB6Q/xU45B9mlDELr+U6JRsdbAHSATKGWENVbTNcw0DvaprHT2l2fhSqrN81pTuFvV6VH3b0YNqLVdwUiVvZ13/1MTeDyCk0CCf5ejkbP2WaVwOdzDjL79K6dhjzIjggT6Ggzw/VrPwJ6WTwE+IVOkmCdBocCwIDAQAB`

and make your Alfresco authentication chain is aware of the identity-service authentication
* authentication.chain=identity-service1:identity-service

Spring Cloud Gateway
-
This is a Spring Boot application that you need to start

* it comes with a predefined JKS (keystore) containg the public key referenced earlier. It is recommended that you use your own set of private/public keys

Here are some useful URLs
* http://localhost:9595/logout
* http://localhost:9595/share
* http://localhost:9595/alfresco

The gateway is configured to use emails as usernames and this is a fully spring security configuration so feel free to enhance it with your needs. If you need to add more than a single local user (admin:password) than have a look at how to do it within Spring Security. Also, please make sure that you understand that the user has to exist inside of alfresco and that the authorization part is still done by Alfresco (user/groups management). You also might use Alfresco Synchronization in order to retrieve the users/groups from LDAP or any other directory.

Make sure to correctly configure your OAuth2 providers redirect URIs. Facebook does not require a special configuration for http://localhost redirects but Google does.
* https://console.developers.google.com/
* https://developers.facebook.com/

No JWT or JKS config has been externalized, thus if you do not use Alfresco defaults for Identity Services make sure to adapt them in `com.gradecak.alfresco.jwt.gateway.filter.JwtBearerAuthorizationHeaderGatewayFilterFactory.createToken(JWSSigner, String)`

ADF applications
-
I will not provide a working ACA or any ADF apps. Please refer to [ADF with Kerberos or with External Auth](https://www.alfresco.com/abn/adf/docs/user-guide/kerberos/) in order to see how to do it.

Please remember that in order to benefit of the Spring Cloud Gateway SSO the ADF application has to be behind the proxy too. So, a new entry in application.yml of the gateway project is needed.

    cloud.gateway.routes:
        - id: aca
          uri: http://localhost:4200
          predicates:
            - Path=/aca/**
          filters:            
            - JwtBearerAuthorizationHeader

Supported Alfresco versions
----
- should work on any ACS versions supporting Alfresco Identity Services.
- enables OAuth2 in Alfresco Share
