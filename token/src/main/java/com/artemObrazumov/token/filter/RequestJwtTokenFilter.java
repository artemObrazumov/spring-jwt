package com.artemObrazumov.token.filter;

import com.artemObrazumov.token.Token;
import com.artemObrazumov.token.dto.Tokens;
import com.artemObrazumov.token.factory.AccessTokenFactory;
import com.artemObrazumov.token.factory.RefreshTokenFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.function.Function;

public class RequestJwtTokenFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/jwt/tokens", HttpMethod.POST.name());

    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private Function<Authentication, Token> refreshTokenFactory = new RefreshTokenFactory();

    private Function<Token, Token> accessTokenFactory = new AccessTokenFactory();

    private Function<Token, String> refreshTokenStringSerializer;

    private Function<Token, String> accessTokenStringSerializer;

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            if (this.securityContextRepository.containsContext(request)) {
                var context = this.securityContextRepository.loadDeferredContext(request).get();
                if (context != null && !(context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken)) {
                    var refreshToken = this.refreshTokenFactory.apply(context.getAuthentication());
                    var accessToken = this.accessTokenFactory.apply(refreshToken);

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    var refreshTokenString = this.refreshTokenStringSerializer.apply(refreshToken);
                    var accessTokenString = this.accessTokenStringSerializer.apply(accessToken);
                    var tokens = new Tokens(accessTokenString, accessToken.expiresAt().toString(),
                            refreshTokenString, refreshToken.expiresAt().toString());
                    this.objectMapper.writeValue(response.getWriter(), tokens);
                    return;
                }
            }
            throw new AccessDeniedException("User must be authenticated");
        }

        filterChain.doFilter(request, response);
    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    public void setRefreshTokenFactory(Function<Authentication, Token> refreshTokenFactory) {
        this.refreshTokenFactory = refreshTokenFactory;
    }

    public void setAccessTokenFactory(Function<Token, Token> accessTokenFactory) {
        this.accessTokenFactory = accessTokenFactory;
    }

    public void setRefreshTokenStringSerializer(Function<Token, String> refreshTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
    }

    public void setAccessTokenStringSerializer(Function<Token, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
}
