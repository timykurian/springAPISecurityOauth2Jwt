package com.agapae.sec.oauth.jwt.ds.config;

import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
/**
 * Configuration class for enabling global method security.
 * It is annotated with {@link EnableGlobalMethodSecurity},
 * enabling Spring Security's method-level security features,
 * such as pre and post annotations for method authorization.
 */
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration {

}
