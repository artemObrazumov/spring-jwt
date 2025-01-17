package com.artemObrazumov.token;

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
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@ComponentScan(basePackages = {"com.artemObrazumov.token"})
@EntityScan(basePackages = {"com.artemObrazumov.token"})
@EnableJpaRepositories(basePackages = {"com.artemObrazumov.token"})
public class JWTAuthConfig {

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
}
