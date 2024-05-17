package com.agapae.sec.oauth.jwt.ds.config;

import org.apache.commons.io.IOUtils;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
/**
 * Configuration class for setting up the Resource Server in OAuth 2.0 protocol.
 * It extends  ResourceServerConfigurerAdapter which provides
 *  default implementations of the Resource Server.
 * This class is annotated with  Configuration, EnableResourceServer,
 * EnableConfigurationProperties
 * enabling the Resource Server to authenticate requests using OAuth 2.0 tokens
 * and binding configuration properties defined in  SecurityProperties.
 */
@Configuration
@EnableResourceServer
@EnableConfigurationProperties(com.agapae.sec.oauth.jwt.ds.config.SecurityProperties.class)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private static final String ROOT_PATTERN = "/**";

    private final com.agapae.sec.oauth.jwt.ds.config.SecurityProperties securityProperties;

    private TokenStore tokenStore;

    /**
     * Constructs an instance of ResourceServerConfiguration.
     *
     * @param securityProperties Security properties containing JWT configuration.
     */
    public ResourceServerConfiguration(final com.agapae.sec.oauth.jwt.ds.config.SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    /**
     * Configures the resource server security with the token store.
     *
     * @param resources ResourceServerSecurityConfigurer instance.
     */
    @Override
    public void configure(final ResourceServerSecurityConfigurer resources) {
        resources.tokenStore(tokenStore());
    }

    /**
     * Configures HTTP security for the resource server.
     *
     * @param http HttpSecurity instance.
     * @throws Exception If an error occurs during configuration.
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET, ROOT_PATTERN).access("#oauth2.hasScope('read')")
                .antMatchers(HttpMethod.POST, ROOT_PATTERN).access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PATCH, ROOT_PATTERN).access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PUT, ROOT_PATTERN).access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.DELETE, ROOT_PATTERN).access("#oauth2.hasScope('write')");
    }

    /**
     * Provides a bean for DefaultTokenServices.
     *
     * @param tokenStore TokenStore instance.
     * @return DefaultTokenServices bean.
     */
    @Bean
    public DefaultTokenServices tokenServices(final TokenStore tokenStore) {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore);
        return tokenServices;
    }

    /**
     * Provides a bean for TokenStore.
     *
     * @return TokenStore bean.
     */
    @Bean
    public TokenStore tokenStore() {
        if (tokenStore == null) {
            tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
        }
        return tokenStore;
    }

    /**
     * Provides a bean for JwtAccessTokenConverter.
     *
     * @return JwtAccessTokenConverter bean.
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setVerifierKey(getPublicKeyAsString());
        return converter;
    }

    /**
     * Retrieves the public key as a String from the security properties.
     *
     * @return Public key as a String.
     */
    private String getPublicKeyAsString() {
        try {
            return IOUtils.toString(securityProperties.getJwt().getPublicKey().getInputStream(), UTF_8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
