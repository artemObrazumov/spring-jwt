package com.artemObrazumov.jwt_implementation.token;

import com.artemObrazumov.jwt_implementation.token.filter.RequestJwtTokenFilter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.function.Function;

public class JWTAuthConfigurer extends AbstractHttpConfigurer<JWTAuthConfigurer, HttpSecurity> {

    private Function<Token, String> refreshTokenStringSerializer;

    private Function<Token, String> accessTokenStringSerializer;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            csrfConfigurer.ignoringRequestMatchers(
                    new AntPathRequestMatcher("/jwt/tokens", HttpMethod.POST.name()));
        }
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        var requestJwtFilter = new RequestJwtTokenFilter();
        requestJwtFilter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);
        requestJwtFilter.setRefreshTokenStringSerializer(this.refreshTokenStringSerializer);

        builder.addFilterAfter(requestJwtFilter, BasicAuthenticationFilter.class);
    }

    public void setRefreshTokenStringSerializer(Function<Token, String> refreshTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
    }

    public void setAccessTokenStringSerializer(Function<Token, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }
}
