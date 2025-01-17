package com.artemObrazumov.token;

import com.artemObrazumov.token.converter.JWTAuthConverter;
import com.artemObrazumov.token.filter.JwtLogoutFilter;
import com.artemObrazumov.token.filter.RequestAccessTokenFilter;
import com.artemObrazumov.token.filter.RequestJwtTokenFilter;
import com.artemObrazumov.token.repository.DeactivatedTokensRepository;
import com.artemObrazumov.token.user.TokenAuthenticationUserDetailService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.function.Function;

public class JWTAuthConfigurer extends AbstractHttpConfigurer<JWTAuthConfigurer, HttpSecurity> {

    private Function<Token, String> refreshTokenStringSerializer;

    private Function<Token, String> accessTokenStringSerializer;

    private Function<String, Token> accessTokenStringDeserializer;

    private Function<String, Token> refreshTokenStringDeserializer;

    private DeactivatedTokensRepository deactivatedTokensRepository;

    @Override
    public void init(HttpSecurity builder) {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            csrfConfigurer.ignoringRequestMatchers(
                    new AntPathRequestMatcher("/jwt/tokens", HttpMethod.POST.name()));
        }
    }

    @Override
    public void configure(HttpSecurity builder) {
        var requestJwtFilter = new RequestJwtTokenFilter();
        requestJwtFilter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);
        requestJwtFilter.setRefreshTokenStringSerializer(this.refreshTokenStringSerializer);

        builder.addFilterAfter(requestJwtFilter, ExceptionTranslationFilter.class);

        var jwtAuthFilter = new AuthenticationFilter(builder.getSharedObject(AuthenticationManager.class),
                new JWTAuthConverter(this.accessTokenStringDeserializer, this.refreshTokenStringDeserializer));
        jwtAuthFilter.setSuccessHandler(((request, response, authentication) -> {
            CsrfFilter.skipRequest(request);
        }));
        jwtAuthFilter.setFailureHandler(((request, response, exception) -> {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }));

        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(
                new TokenAuthenticationUserDetailService(deactivatedTokensRepository));
        builder.addFilterBefore(jwtAuthFilter, CsrfFilter.class)
                .authenticationProvider(authenticationProvider);

        var accessTokenFilter = new RequestAccessTokenFilter();
        accessTokenFilter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);

        builder.addFilterAfter(accessTokenFilter, ExceptionTranslationFilter.class);

        var logoutFilter = new JwtLogoutFilter(deactivatedTokensRepository);
        builder.addFilterAfter(logoutFilter, ExceptionTranslationFilter.class);
    }

    public void setRefreshTokenStringSerializer(Function<Token, String> refreshTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
    }

    public void setAccessTokenStringSerializer(Function<Token, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }

    public void setAccessTokenStringDeserializer(Function<String, Token> accessTokenStringDeserializer) {
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
    }

    public void setRefreshTokenStringDeserializer(Function<String, Token> refreshTokenStringDeserializer) {
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
    }

    public void setDeactivatedTokensRepository(DeactivatedTokensRepository deactivatedTokensRepository) {
        this.deactivatedTokensRepository = deactivatedTokensRepository;
    }
}
