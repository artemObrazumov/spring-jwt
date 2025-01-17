package com.artemObrazumov.token.filter;

import com.artemObrazumov.token.entity.DeactivatedToken;
import com.artemObrazumov.token.repository.DeactivatedTokensRepository;
import com.artemObrazumov.token.user.TokenUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.sql.Date;

public class JwtLogoutFilter extends OncePerRequestFilter {

    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/jwt/logout", HttpMethod.POST.name());

    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final DeactivatedTokensRepository deactivatedTokensRepository;

    public JwtLogoutFilter(DeactivatedTokensRepository deactivatedTokensRepository) {
        this.deactivatedTokensRepository = deactivatedTokensRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (requestMatcher.matches(request)) {
            if (this.securityContextRepository.containsContext(request)) {
                var context = this.securityContextRepository.loadDeferredContext(request).get();
                if (context != null && context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken &&
                        context.getAuthentication().getPrincipal() instanceof TokenUser user &&
                        context.getAuthentication().getAuthorities()
                                .contains(new SimpleGrantedAuthority("JWT_REFRESH"))
                ) {
                    this.deactivatedTokensRepository.save(
                            new DeactivatedToken(user.getToken().id(), Date.from(user.getToken().expiresAt()))
                    );
                    response.setStatus(HttpServletResponse.SC_OK);
                    return;
                }
            }
            throw new AccessDeniedException("User must be authenticated with JWT");
        }

        filterChain.doFilter(request, response);
    }
}
