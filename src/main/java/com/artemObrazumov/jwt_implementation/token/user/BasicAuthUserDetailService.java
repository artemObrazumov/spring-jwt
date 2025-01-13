package com.artemObrazumov.jwt_implementation.token.user;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class BasicAuthUserDetailService implements UserDetailsService {

    private final JdbcTemplate jdbcTemplate;

    public BasicAuthUserDetailService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        var password = jdbcTemplate.queryForObject("""
                select c_password from t_user where c_username = ?
                """, String.class, username);

        return User.builder()
                .username(username)
                .password(password)
                .build();
    }
}
