package com.agapae.sec.oauth.jwt.config.props;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
/**
 * Configuration properties for security settings related to JWT (JSON Web Token) authentication.
 * This class is annotated with {@link ConfigurationProperties}, indicating that it binds to the properties
 * defined in the application configuration file (application.yml or application.properties) under the "security" prefix.
 */
@ConfigurationProperties("security")
public class SecurityProperties {

    /**
     * JWT (JSON Web Token) properties containing details about the key store, key store password, key pair alias,
     * and key pair password used for JWT authentication.
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
     * Inner class representing JWT properties containing details about the key store, key store password,
     * key pair alias, and key pair password used for JWT authentication.
     */
    public static class JwtProperties {

        /**
         * Resource representing the location of the key store file.
         */
        private Resource keyStore;

        /**
         * Password to access the key store.
         */
        private String keyStorePassword;

        /**
         * Alias of the key pair within the key store.
         */
        private String keyPairAlias;

        /**
         * Password to access the key pair.
         */
        private String keyPairPassword;

        /**
         * Get the resource representing the location of the key store file.
         *
         * @return Key store resource.
         */
        public Resource getKeyStore() {
            return keyStore;
        }

        /**
         * Set the resource representing the location of the key store file.
         *
         * @param keyStore Key store resource.
         */
        public void setKeyStore(Resource keyStore) {
            this.keyStore = keyStore;
        }

        /**
         * Get the password to access the key store.
         *
         * @return Key store password.
         */
        public String getKeyStorePassword() {
            return keyStorePassword;
        }

        /**
         * Set the password to access the key store.
         *
         * @param keyStorePassword Key store password.
         */
        public void setKeyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }

        /**
         * Get the alias of the key pair within the key store.
         *
         * @return Key pair alias.
         */
        public String getKeyPairAlias() {
            return keyPairAlias;
        }

        /**
         * Set the alias of the key pair within the key store.
         *
         * @param keyPairAlias Key pair alias.
         */
        public void setKeyPairAlias(String keyPairAlias) {
            this.keyPairAlias = keyPairAlias;
        }

        /**
         * Get the password to access the key pair.
         *
         * @return Key pair password.
         */
        public String getKeyPairPassword() {
            return keyPairPassword;
        }

        /**
         * Set the password to access the key pair.
         *
         * @param keyPairPassword Key pair password.
         */
        public void setKeyPairPassword(String keyPairPassword) {
            this.keyPairPassword = keyPairPassword;
        }
    }
}


