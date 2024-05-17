package com.agapae.sec.oauth.jwt.ds.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
/**
 * Configuration properties for security settings related to
 * JWT (JSON Web Token) authentication.
 * This class is annotated with ConfigurationProperties  indicating that it binds to the properties
 * defined in the application configuration file (application.yml or application.properties)
 * under the "security" prefix.
 */
@ConfigurationProperties("security")
public class SecurityProperties {

    /**
     * JWT (JSON Web Token) properties containing details about the public key used for token verification.
     */
    private JwtProperties jwt;

    /**
     * Get the JWT properties.
     *
     * @return JWT properties.
     */
    public JwtProperties getJwt() {
        return jwt;
    }

    /**
     * Set the JWT properties.
     *
     * @param jwt JWT properties.
     */
    public void setJwt(JwtProperties jwt) {
        this.jwt = jwt;
    }

    /**
     * Inner class representing JWT properties containing details about the public key used for token verification.
     */
    public static class JwtProperties {

        /**
         * Resource representing the public key used for token verification.
         */
        private Resource publicKey;

        /**
         * Get the resource representing the public key.
         *
         * @return Public key resource.
         */
        public Resource getPublicKey() {
            return publicKey;
        }

        /**
         * Set the resource representing the public key.
         *
         * @param publicKey Public key resource.
         */
        public void setPublicKey(Resource publicKey) {
            this.publicKey = publicKey;
        }
    }
}
