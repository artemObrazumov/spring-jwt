package com.artemObrazumov.token.user;

import com.artemObrazumov.token.entity.UserAuthority;
import com.artemObrazumov.token.repository.UserAuthorityRepository;
import com.artemObrazumov.token.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class BasicAuthUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;
    private final UserAuthorityRepository userAuthorityRepository;

    public BasicAuthUserDetailService(UserRepository userRepository, UserAuthorityRepository userAuthorityRepository) {
        this.userRepository = userRepository;
        this.userAuthorityRepository = userAuthorityRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            var user = userRepository.findByName(username).orElseThrow(() ->
                    new UsernameNotFoundException("User not found")
            );

            var authorities = userAuthorityRepository.findByUserId(user.getId());

            return User.builder()
                    .username(user.getName())
                    .password(user.getPassword())
                    .authorities(authorities.stream()
                            .map(UserAuthority::getAuthority)
                            .map(SimpleGrantedAuthority::new)
                            .toList())
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
