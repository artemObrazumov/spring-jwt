package com.artemObrazumov.jwt_implementation;

import com.artemObrazumov.token.JWTAuthConfigurer;
import com.artemObrazumov.token.deserializer.AccessTokenJwsStringDeserializer;
import com.artemObrazumov.token.deserializer.RefreshTokenJwsStringDeserializer;
import com.artemObrazumov.token.repository.DeactivatedTokensRepository;
import com.artemObrazumov.token.repository.UserAuthorityRepository;
import com.artemObrazumov.token.repository.UserRepository;
import com.artemObrazumov.token.serializer.AccessTokenJwsStringSerializer;
import com.artemObrazumov.token.serializer.RefreshTokenJweStringSerializer;
import com.artemObrazumov.token.user.BasicAuthUserDetailService;
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
