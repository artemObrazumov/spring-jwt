package com.artemObrazumov.token.user;

import com.artemObrazumov.token.Token;
import com.artemObrazumov.token.repository.DeactivatedTokensRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;

public class TokenAuthenticationUserDetailService implements
        AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final DeactivatedTokensRepository deactivatedTokensRepository;

    public TokenAuthenticationUserDetailService(DeactivatedTokensRepository deactivatedTokensRepository) {
        this.deactivatedTokensRepository = deactivatedTokensRepository;
    }

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authToken) throws UsernameNotFoundException {
        if (authToken.getPrincipal() instanceof Token token) {
            var isDeactivated = deactivatedTokensRepository.existsById(token.id());
            var authorities = token.authorities()
                    .stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList();
            return new TokenUser(token.subject(), "nopassword", true, !isDeactivated,
                    token.expiresAt().isAfter(Instant.now()), true, authorities, token);
        }
        throw new UsernameNotFoundException("Principal must be of type token");
    }
}
