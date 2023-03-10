package com.security.demo.config;

import java.io.StringReader;
import java.time.Instant;
import java.util.Date;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.xml.sax.InputSource;

/**
 *
 * This class extracts the SAML2 token expiry and adds it to the session
 */
public final class SAML2TokenExpirySessionAuthenticationStrategy implements SessionAuthenticationStrategy {

    public static final String SAML2_TOKEN_EXPIRY = "SAML2_TOKEN_EXPIRY";
    private XPathExpression notOnOrAfterXPath;

    public SAML2TokenExpirySessionAuthenticationStrategy() throws XPathExpressionException {
        XPath xPath = XPathFactory.newInstance().newXPath();
        notOnOrAfterXPath =
            xPath.compile(
                "//*[local-name() = 'Assertion' and namespace-uri() = 'urn:oasis:names:tc:SAML:2.0:assertion']/*[local-name() = 'Conditions' and namespace-uri() = 'urn:oasis:names:tc:SAML:2.0:assertion']/@NotOnOrAfter"
            );
    }

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
        throws SessionAuthenticationException {
        if (authentication instanceof Saml2Authentication) {
            Object expiry = request.getSession().getAttribute(SAML2TokenExpirySessionAuthenticationStrategy.SAML2_TOKEN_EXPIRY);
            if (expiry == null) {
                Saml2Authentication token = (Saml2Authentication) authentication;
                InputSource inputXML = new InputSource(new StringReader(token.getSaml2Response()));
                try {
                    String notOnOrAfter = notOnOrAfterXPath.evaluate(inputXML);
                    Instant tokenExpiry = Instant.parse(notOnOrAfter);
                    request.getSession().setAttribute(SAML2_TOKEN_EXPIRY, tokenExpiry);
                } catch (XPathExpressionException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
