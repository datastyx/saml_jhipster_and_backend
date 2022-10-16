package com.security.demo.config;

import com.security.demo.security.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.filter.CorsFilter;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;
import tech.jhipster.config.JHipsterProperties;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Import(SecurityProblemSupport.class)
public class SecurityConfiguration {

    private final JHipsterProperties jHipsterProperties;

    private final CorsFilter corsFilter;

    public SecurityConfiguration(CorsFilter corsFilter, JHipsterProperties jHipsterProperties) {
        this.corsFilter = corsFilter;
        this.jHipsterProperties = jHipsterProperties;
    }

    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {
        Converter<ResponseToken, Saml2Authentication> delegate = OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

        return responseToken -> {
            Saml2Authentication authentication = delegate.convert(responseToken);
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
            List<String> groups = principal.getAttribute("groups");
            Set<GrantedAuthority> authorities = new HashSet<>();
            if (groups != null) {
                groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
            } else {
                authorities.addAll(authentication.getAuthorities());
            }
            return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());

        http
            .csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http
           .addFilterBefore(corsFilter, CsrfFilter.class);
      
        http            
            .headers()
                .contentSecurityPolicy(jHipsterProperties.getSecurity().getContentSecurityPolicy())
            .and()
                .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
            .and()
                .permissionsPolicy().policy("camera=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), sync-xhr=()")
            .and()
                .frameOptions().sameOrigin()
            .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .antMatchers("/app/**/*.{js,html}").permitAll()
                .antMatchers("/i18n/**").permitAll()
                .antMatchers("/content/**").permitAll()
                .antMatchers("/swagger-ui/**").permitAll()
                .antMatchers("/test/**").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/admin/**").hasAuthority(AuthoritiesConstants.ADMIN)
                .antMatchers("/api/**").authenticated()
                .antMatchers("/management/health").permitAll()
                .antMatchers("/management/health/**").permitAll()
                .antMatchers("/management/info").permitAll()
                .antMatchers("/management/prometheus").permitAll()
                .antMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
                ;
        http.saml2Login(saml2 -> saml2
                .authenticationManager(new ProviderManager(authenticationProvider)));
        // http.saml2Login();
        http.logout(logout -> logout.logoutSuccessUrl("/"));

        return http.build();
        // @formatter:on
    }
}
