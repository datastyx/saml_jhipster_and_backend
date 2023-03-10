package com.security.demo.config;

import java.time.Instant;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class TokenExpiryAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Instant tokenExpiry = (Instant) ((ExpiryAuthentication) authentication).getCredentials();

        if (tokenExpiry.isBefore(Instant.now())) {
            authentication.setAuthenticated(false);
            return authentication;
        } else {
            authentication.setAuthenticated(true);
            return authentication; // Null makes the ProviderManager pass the auth to the SAML2 authentication
            // provider
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(ExpiryAuthentication.class);
    }
}
