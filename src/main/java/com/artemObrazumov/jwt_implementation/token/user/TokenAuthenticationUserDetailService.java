package com.artemObrazumov.jwt_implementation.token.user;

import com.artemObrazumov.jwt_implementation.token.Token;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;

public class TokenAuthenticationUserDetailService implements
        AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private JdbcTemplate jdbcTemplate;

    public TokenAuthenticationUserDetailService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authToken) throws UsernameNotFoundException {
        if (authToken.getPrincipal() instanceof Token token) {
            var isDeactivated = this.jdbcTemplate.queryForObject("""
                    select exists(select id from t_deactivated_token where id = ?)
                    """, Boolean.class, token.id());
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
