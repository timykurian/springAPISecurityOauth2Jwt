package com.agapae.sec.oauth.jwt.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

/**
 *  centralize and organize  security configurations in a single class,
 *  making it easier to manage and maintain the security of the application.
 */
/**
 * Configuration class for setting up web security in the application.
 * It extends WebSecurityConfigurerAdapter providing default security configurations
 * for web-based security.
 * This class is annotated with  EnableWebSecurity,
 * enabling Spring Security's web security features.
 *
 *
 * It specifies which users are allowed to access specific URLs
 * or endpoints and what roles or authorities they need to have.
 */
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final DataSource dataSource;

    private PasswordEncoder passwordEncoder;
    private UserDetailsService userDetailsService;

    /**
     * Constructs an instance of WebSecurityConfiguration.
     *
     * @param dataSource DataSource for accessing user details and authentication information.
     */
    public WebSecurityConfiguration(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * Configures the authentication manager with user details service and password encoder.
     *
     * @param auth AuthenticationManagerBuilder instance.
     * @throws Exception If an error occurs during configuration.
     */
    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder());
    }

    /**
     * Provides a bean for AuthenticationManager.
     *
     * @return AuthenticationManager bean.
     * @throws Exception If an error occurs while creating the bean.
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Provides a bean for PasswordEncoder.
     *
     * @return PasswordEncoder bean.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        if (passwordEncoder == null) {
            passwordEncoder = DefaultPasswordEncoderFactories.createDelegatingPasswordEncoder();
        }
        return passwordEncoder;
    }

    /**
     * Provides a bean for UserDetailsService.
     *
     * @return UserDetailsService bean.
     */
    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        if (userDetailsService == null) {
            userDetailsService = new JdbcDaoImpl();
            ((JdbcDaoImpl) userDetailsService).setDataSource(dataSource);
        }
        return userDetailsService;
    }
}

