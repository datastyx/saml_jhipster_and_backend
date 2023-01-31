package com.security.demo.config;

import com.security.demo.client.ActAsCallbackHandler;
import com.security.demo.client.ClaimsCallbackHandler;
import com.security.demo.client.SAML2stsCallbackHandler;
import com.security.demo.client.UsernameTokenSubCallbackHandler;
import com.security.demo.common.ISubCallbackHandler;
import com.security.demo.common.KeystoreSubCallbackHandler;
import com.security.demo.common.WSPasswordCallbackHandler;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.namespace.QName;
import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBus;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.rt.security.SecurityConstants;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.hello_world_soap_http.Greeter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClientConfiguration {

    @Value("${client.user.name}")
    String clientUsername;

    @Value("${client.sts.merlin.propertyfile}")
    String merlinPropertyFile;

    @Value("${client.sts.keystore.user.encrypt.pubkey.alias}")
    String encryptionUsername;

    @Value("${client.keystore.user.pubkey.alias}")
    String stsTokenUsername;

    String keystoreLocation = "/clientKeystore.jks";
    String keystorePassword = "client";
    String keyPassword = "client";

    String stsTokenProperties = "src/main/resources/clientKeystore.properties";

    String stsURL = "https://localhost:8090/SecurityTokenService/UT"; // endpoint of the STS to retrieve delegation tokens

    String wsdlLocation = "src/main/resources/hello_world.wsdl";
    QName serviceName = new QName("http://apache.org/hello_world_soap_http", "SOAPService");
    QName endpointName = new QName("http://apache.org/hello_world_soap_http", "SoapPort");

    LoggingFeature loggingFeature() {
        return new LoggingFeature();
    }

    @Bean(name = Bus.DEFAULT_BUS_ID)
    public SpringBus cxf() {
        return new SpringBus();
    }

    private static TrustManager[] getTrustManagers(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException {
        String alg = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory fac = TrustManagerFactory.getInstance(alg);
        fac.init(trustStore);
        return fac.getTrustManagers();
    }

    private static KeyManager[] getKeyManagers(KeyStore keyStore, String keyPassword) throws GeneralSecurityException, IOException {
        String alg = KeyManagerFactory.getDefaultAlgorithm();
        char[] keyPass = keyPassword != null ? keyPassword.toCharArray() : null;
        KeyManagerFactory fac = KeyManagerFactory.getInstance(alg);
        fac.init(keyStore, keyPass);
        return fac.getKeyManagers();
    }

    @Bean
    ClaimsCallbackHandler claimsCallbackHandler() {
        return new ClaimsCallbackHandler();
    }

    @Bean
    KeystoreSubCallbackHandler keystoreSubCallbackHandler() {
        return new KeystoreSubCallbackHandler("client");
    }

    @Bean
    UsernameTokenSubCallbackHandler usernameTokenSubCallbackHandler() {
        return new UsernameTokenSubCallbackHandler();
    }

    @Bean
    WSPasswordCallbackHandler wsPasswordCallbackHandler() {
        final List<ISubCallbackHandler> list = new ArrayList<ISubCallbackHandler>();
        list.add(keystoreSubCallbackHandler());
        list.add(usernameTokenSubCallbackHandler());
        WSPasswordCallbackHandler wsPasswordCallbackHandler = new WSPasswordCallbackHandler();
        wsPasswordCallbackHandler.setSubCallbackHandlers(list);
        return wsPasswordCallbackHandler;
    }

    @Bean
    ActAsCallbackHandler actAsCallbackHandler() {
        return new ActAsCallbackHandler();
    }

    @Bean
    STSClient stsClient() throws IOException, GeneralSecurityException {
        STSClient stsClient = new STSClient(cxf());
        stsClient.setRequiresEntropy(false);
        stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey");
        stsClient.setAddressingNamespace("http://schemas.xmlsoap.org/ws/2004/08/addressing");
        stsClient.setWsdlLocation("src/main/resources/ws-trust.wsdl");
        stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}wso2carbon-sts");
        stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}wso2carbon-stsHttpsSoap12Endpoint");
        stsClient.setClaimsCallbackHandler(claimsCallbackHandler());
        stsClient.setFeatures(Arrays.asList(loggingFeature()));
        stsClient.setActAs(actAsCallbackHandler());
        final Map<String, Object> propertyMap = new HashMap<String, Object>();
        propertyMap.put("security.username", clientUsername);
        propertyMap.put("security.encryption.properties", merlinPropertyFile);
        propertyMap.put("security.encryption.username", encryptionUsername);
        propertyMap.put("security.sts.token.username", stsTokenUsername);
        propertyMap.put("security.sts.token.properties", stsTokenProperties);
        propertyMap.put("security.sts.token.usecert", "true");
        propertyMap.put("security.callback-handler", wsPasswordCallbackHandler());

        stsClient.setProperties(propertyMap);
        stsClient.setTlsClientParameters(tlsClientParameters());
        return stsClient;
    }

    @Bean
    SAML2stsCallbackHandler saml2stsCallbackHandler() throws IOException, GeneralSecurityException {
        SAML2stsCallbackHandler saml2stsCallbackHandler = new SAML2stsCallbackHandler(stsURL);
        saml2stsCallbackHandler.setStsClient(stsClient());

        return saml2stsCallbackHandler;
    }

    @Bean
    JaxWsProxyFactoryBean wssProxyFactory() throws IOException, GeneralSecurityException {
        JaxWsProxyFactoryBean jaxWsProxyFactoryBean = new JaxWsProxyFactoryBean();
        jaxWsProxyFactoryBean.setBus(cxf());
        jaxWsProxyFactoryBean.setServiceClass(org.apache.hello_world_soap_http.Greeter.class);
        jaxWsProxyFactoryBean.setWsdlLocation(wsdlLocation);
        jaxWsProxyFactoryBean.setServiceName(serviceName);
        jaxWsProxyFactoryBean.setEndpointName(endpointName);
        jaxWsProxyFactoryBean.setFeatures(Arrays.asList(loggingFeature()));
        final Map<String, Object> propertyMap = new HashMap<String, Object>();
        propertyMap.put("security.callback-handler", wsPasswordCallbackHandler());
        propertyMap.put("security.signature.properties", "clientKeystore.properties");
        propertyMap.put("security.saml-callback-handler", saml2stsCallbackHandler());
        jaxWsProxyFactoryBean.setProperties(propertyMap);
        return jaxWsProxyFactoryBean;
    }

    @Bean
    Greeter greeter() throws IOException, GeneralSecurityException {
        Greeter greeter = (Greeter) wssProxyFactory().create();
        org.apache.cxf.endpoint.Client proxy = ClientProxy.getClient(greeter);
        HTTPConduit conduit = (HTTPConduit) proxy.getConduit();
        conduit.setTlsClientParameters(tlsClientParameters());

        return greeter;
    }

    @Bean
    TLSClientParameters tlsClientParameters() throws IOException, GeneralSecurityException {
        TLSClientParameters tlsClientParameters = new TLSClientParameters();
        // TODO has to be checked in production
        tlsClientParameters.setDisableCNCheck(true);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ClientConfiguration.class.getResourceAsStream(keystoreLocation), keystorePassword.toCharArray());
        KeyManager[] keyManagers = getKeyManagers(keyStore, keyPassword);
        tlsClientParameters.setKeyManagers(keyManagers);
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(ClientConfiguration.class.getResourceAsStream(keystoreLocation), keystorePassword.toCharArray());
        tlsClientParameters.setTrustManagers(getTrustManagers(trustStore));
        return tlsClientParameters;
    }
}
