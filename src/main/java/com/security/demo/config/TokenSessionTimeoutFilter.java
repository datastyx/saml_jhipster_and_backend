package com.security.demo.config;

import java.io.IOException;
import java.time.Instant;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFilter;

public class TokenSessionTimeoutFilter extends AuthenticationFilter {

    private SessionRegistry sessionRegistry;

    public TokenSessionTimeoutFilter(
        AuthenticationManager authenticationManager,
        AuthenticationConverter authenticationConverter,
        SessionRegistry sessionRegistry
    ) {
        super(authenticationManager, authenticationConverter);
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        Instant expiry = (Instant) request.getSession().getAttribute(SAML2TokenExpirySessionAuthenticationStrategy.SAML2_TOKEN_EXPIRY);
        if (!this.getRequestMatcher().matches(request)) {
            if (logger.isTraceEnabled()) {
                logger.trace("Did not match request to " + this.getRequestMatcher());
            }
            filterChain.doFilter(request, response);
            return;
        }
        if (expiry != null && expiry.isBefore(Instant.now().plusMillis(4000 * 60))) {
            SessionInformation sessionInformation = sessionRegistry.getSessionInformation(request.getSession().getId());
            if (sessionInformation != null) {
                sessionInformation.expireNow();
            }

            // this.getAuthenticationManagerResolver().resolve(request).authenticate(new
            // ExpiryAuthentication(expiry));

            // SecurityContextHolder.clearContext();

            // request.getSession().;
            // SecurityContextHolder.clearContext();
            // this.getFailureHandler().onAuthenticationFailure(request,response,new
            // CredentialsExpiredException("SAML2 Token Expired"));
            filterChain.doFilter(request, response);
            // throw new CredentialsExpiredException("SAML2 Token Expired");
        }
        filterChain.doFilter(request, response);
    }
}
