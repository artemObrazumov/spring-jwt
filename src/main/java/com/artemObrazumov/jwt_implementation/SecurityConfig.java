package com.artemObrazumov.jwt_implementation;

import com.artemObrazumov.jwt_implementation.token.JWTAuthConfigurer;
import com.artemObrazumov.jwt_implementation.token.deserializer.AccessTokenJwsStringDeserializer;
import com.artemObrazumov.jwt_implementation.token.deserializer.RefreshTokenJwsStringDeserializer;
import com.artemObrazumov.jwt_implementation.token.repository.DeactivatedTokensRepository;
import com.artemObrazumov.jwt_implementation.token.repository.UserAuthorityRepository;
import com.artemObrazumov.jwt_implementation.token.repository.UserRepository;
import com.artemObrazumov.jwt_implementation.token.serializer.AccessTokenJwsStringSerializer;
import com.artemObrazumov.jwt_implementation.token.serializer.RefreshTokenJweStringSerializer;
import com.artemObrazumov.jwt_implementation.token.user.BasicAuthUserDetailService;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(
            UserRepository userRepository,
            UserAuthorityRepository userAuthorityRepository
    ) {
        return new BasicAuthUserDetailService(userRepository, userAuthorityRepository);
    }

    @Bean
    public JWTAuthConfigurer jwtAuthConfigurer(
            @Value("${jwt.access-token-key}") String accessTokenKey,
            @Value("${jwt.refresh-token-key}") String refreshTokenKey,
            DeactivatedTokensRepository deactivatedTokensRepository
    ) throws Exception {
        var jwtAuthConfigurer = new JWTAuthConfigurer();
        jwtAuthConfigurer.setAccessTokenStringSerializer(
                new AccessTokenJwsStringSerializer(
                        new MACSigner(OctetSequenceKey.parse(accessTokenKey))
                )
        );
        jwtAuthConfigurer.setRefreshTokenStringSerializer(
                new RefreshTokenJweStringSerializer(
                        new DirectEncrypter(OctetSequenceKey.parse(refreshTokenKey))
                )
        );
        jwtAuthConfigurer.setAccessTokenStringDeserializer(
                new AccessTokenJwsStringDeserializer(
                        new MACVerifier(OctetSequenceKey.parse(accessTokenKey))
                )
        );
        jwtAuthConfigurer.setRefreshTokenStringDeserializer(
                new RefreshTokenJwsStringDeserializer(
                        new DirectDecrypter(OctetSequenceKey.parse(refreshTokenKey))
                )
        );
        jwtAuthConfigurer.setDeactivatedTokensRepository(deactivatedTokensRepository);
        return jwtAuthConfigurer;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JWTAuthConfigurer jwtAuthConfigurer) throws Exception {
        return http
                .with(jwtAuthConfigurer, Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorizeHttpRequests ->
                        authorizeHttpRequests
                                .anyRequest().permitAll())
                .build();
    }
}
