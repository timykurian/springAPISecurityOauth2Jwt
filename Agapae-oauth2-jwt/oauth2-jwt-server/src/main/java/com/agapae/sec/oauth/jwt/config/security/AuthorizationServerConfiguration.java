package com.agapae.sec.oauth.jwt.config.security;

import com.agapae.sec.oauth.jwt.config.props.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.security.KeyPair;

/**
 * Configuration class for setting up the Authorization Server in OAuth 2.0 protocol.
 * It extends {@link AuthorizationServerConfigurerAdapter} which provides default implementations of the Authorization Server.
 * This class is annotated with
 * {@link Configuration},
 * {@link EnableAuthorizationServer},
 * and {@link EnableConfigurationProperties},
 * enabling the Authorization Server and binding configuration properties defined in {@link SecurityProperties}.
 */
@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties(SecurityProperties.class)
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private final DataSource dataSource;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final SecurityProperties securityProperties;
    private final UserDetailsService userDetailsService;

    private JwtAccessTokenConverter jwtAccessTokenConverter;
    private TokenStore tokenStore;

    /**
     *
     * @param dataSource              DataSource for JDBC-based client details.
     * @param passwordEncoder         Password encoder for encoding passwords.
     * @param authenticationManager   Authentication manager for handling authentication.
     * @param securityProperties      Security properties containing JWT configuration.
     * @param userDetailsService     Service for loading user-specific data.
     */
    public AuthorizationServerConfiguration(final DataSource dataSource, final PasswordEncoder passwordEncoder,
                                            final AuthenticationManager authenticationManager, final SecurityProperties securityProperties,
                                            final UserDetailsService userDetailsService) {
        this.dataSource = dataSource;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.securityProperties = securityProperties;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Bean definition for TokenStore.
     *
     * @return TokenStore instance.
     */
    @Bean
    public TokenStore tokenStore() {
        if (tokenStore == null) {
            tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
        }
        return tokenStore;
    }

    /**
     * Bean definition for DefaultTokenServices.
     *
     * @param tokenStore           TokenStore implementation.
     * @param clientDetailsService ClientDetailsService instance.
     * @return DefaultTokenServices instance.
     */
    @Bean
    public DefaultTokenServices tokenServices(final TokenStore tokenStore,
                                              final ClientDetailsService clientDetailsService) {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setTokenStore(tokenStore);
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setAuthenticationManager(this.authenticationManager);
        return tokenServices;
    }

    /**
     * Bean definition for JwtAccessTokenConverter.
     *
     * @return JwtAccessTokenConverter instance.
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        if (jwtAccessTokenConverter != null) {
            return jwtAccessTokenConverter;
        }

        SecurityProperties.JwtProperties jwtProperties = securityProperties.getJwt();
        KeyPair keyPair = keyPair(jwtProperties, keyStoreKeyFactory(jwtProperties));

        jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(keyPair);
        return jwtAccessTokenConverter;
    }

    /**
     * Configures the JDBC-based client details.
     *
     * @param clients ClientDetailsServiceConfigurer instance.
     * @throws Exception If an error occurs during configuration.
     */
    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(this.dataSource);
    }

    /**
     * Configures endpoints for the Authorization Server.
     *
     * @param endpoints AuthorizationServerEndpointsConfigurer instance.
     */
    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(this.authenticationManager)
                .accessTokenConverter(jwtAccessTokenConverter())
                .userDetailsService(this.userDetailsService)
                .tokenStore(tokenStore());
    }

    /**
     * Configures security for the Authorization Server.
     *
     * @param oauthServer AuthorizationServerSecurityConfigurer instance.
     */
    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer.passwordEncoder(this.passwordEncoder).tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    /**
     * ******************************   IMP  **************************************
     * Retrieves the KeyPair from the key store using JWT properties.
     *
     * @param jwtProperties     JWT properties.
     * @param keyStoreKeyFactory KeyStoreKeyFactory instance.
     * @return KeyPair instance.
     */
    private KeyPair keyPair(SecurityProperties.JwtProperties jwtProperties, KeyStoreKeyFactory keyStoreKeyFactory) {
        return keyStoreKeyFactory.getKeyPair(jwtProperties.getKeyPairAlias(), jwtProperties.getKeyPairPassword().toCharArray());
    }

    /**
     * Constructs a KeyStoreKeyFactory using JWT properties.
     *
     * @param jwtProperties JWT properties.
     * @return KeyStoreKeyFactory instance.
     */
    private KeyStoreKeyFactory keyStoreKeyFactory(SecurityProperties.JwtProperties jwtProperties) {
        return new KeyStoreKeyFactory(jwtProperties.getKeyStore(), jwtProperties.getKeyStorePassword().toCharArray());
    }
}

