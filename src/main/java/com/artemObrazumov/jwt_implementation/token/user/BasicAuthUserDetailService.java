package com.artemObrazumov.jwt_implementation.token.user;

import com.artemObrazumov.jwt_implementation.token.entity.UserEntity;
import com.artemObrazumov.jwt_implementation.token.repository.UserAuthorityRepository;
import com.artemObrazumov.jwt_implementation.token.repository.UserRepository;
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

        userRepository.save(new UserEntity(null, "j.jameson", "{noop}password"));
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
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
