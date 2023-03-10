package com.security.demo.config;

import java.time.Instant;
import java.util.Collection;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * This authentication contains an expiry date.
 * it is compare to current instant in order to trigger a re authentication.
 */
public class ExpiryAuthentication implements Authentication {

    private Instant expiryInstant;
    private boolean authenticated;

    public ExpiryAuthentication(Instant expiryInstant) {
        this.expiryInstant = expiryInstant;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return expiryInstant;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = authenticated;
    }
}
