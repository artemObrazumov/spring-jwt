package com.artemObrazumov.token.converter;

import com.artemObrazumov.token.Token;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.function.Function;

public class JWTAuthConverter implements AuthenticationConverter {

    private final Function<String, Token> accessTokenStringDeserializer;

    private final Function<String, Token> refreshTokenStringDeserializer;

    public JWTAuthConverter(Function<String, Token> accessTokenStringDeserializer,
                            Function<String, Token> refreshTokenStringDeserializer) {
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        var authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Bearer ")) {
            var token = authorization.replaceFirst("Bearer ", "");
            var accessToken = this.accessTokenStringDeserializer.apply(token);
            if (accessToken != null) {
                return new PreAuthenticatedAuthenticationToken(accessToken, token);
            }
            var refreshToken = this.refreshTokenStringDeserializer.apply(token);
            if (refreshToken != null) {
                return new PreAuthenticatedAuthenticationToken(refreshToken, token);
            }
        }

        return null;
    }
}
