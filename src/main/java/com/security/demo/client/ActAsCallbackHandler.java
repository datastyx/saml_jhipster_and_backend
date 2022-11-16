package com.security.demo.client;

import java.io.IOException;
import java.io.StringReader;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.stream.StreamSource;
import org.apache.cxf.ws.security.trust.delegation.DelegationCallback;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * This CallbackHandler implementation intends to extract a SAML2.0 assertion
 * from the current securityContext.
 */
public class ActAsCallbackHandler implements CallbackHandler {

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof DelegationCallback) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String credential = ((Saml2Authentication) authentication).getSaml2Response();
                Document rstr;
                try {
                    DocumentBuilderFactory factory = DocumentBuilderFactory.newDefaultInstance();
                    factory.setNamespaceAware(true);
                    DocumentBuilder builder = factory.newDocumentBuilder();
                    rstr = builder.parse(new InputSource(new StringReader(credential)));
                    NodeList assertionList = rstr
                        .getDocumentElement()
                        .getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");

                    DelegationCallback callback = (DelegationCallback) callbacks[i];

                    callback.setToken((Element) assertionList.item(0));
                } catch (SAXException | ParserConfigurationException e) {
                    throw new UnsupportedCallbackException(callbacks[i], e.getLocalizedMessage());
                }
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
