package com.agapae.sec.oauth.jwt.config.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Configuration class for setting up the Resource Server in OAuth 2.0 protocol.
 * It extends   ResourceServerConfigurerAdapter
 * which provides default implementations of the Resource Server.
 * This class is annotated with Configuration & EnableResourceServer},
 * enabling the Resource Server to authenticate requests using OAuth 2.0 tokens.
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private final TokenStore tokenStore;

    /**
     * Constructs an instance of ResourceServerConfiguration.
     *
     * @param tokenStore TokenStore implementation used to validate access tokens.
     */
    public ResourceServerConfiguration(final TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    /**
     * Configures the resource server security.
     *
     * @param resources ResourceServerSecurityConfigurer instance.
     */
    @Override
    public void configure(final ResourceServerSecurityConfigurer resources) {
        resources.tokenStore(tokenStore);
    }
}
