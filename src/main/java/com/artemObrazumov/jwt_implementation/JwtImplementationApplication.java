package com.artemObrazumov.jwt_implementation;

import com.artemObrazumov.jwt_implementation.token.JWTAuthConfigurer;
import com.artemObrazumov.jwt_implementation.token.entity.UserEntity;
import com.artemObrazumov.jwt_implementation.token.repository.UserRepository;
import com.artemObrazumov.jwt_implementation.token.serializer.AccessTokenJwsStringSerializer;
import com.artemObrazumov.jwt_implementation.token.serializer.RefreshTokenJweStringSerializer;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity(debug = true)
@SpringBootApplication
public class JwtImplementationApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtImplementationApplication.class, args);
	}

	@Bean
	public CommandLineRunner addSampleUser(
			UserRepository userRepository
	) {
		return args -> {
			userRepository.save(new UserEntity(null, "j.jameson", "{noop}password"));
		};
	}
}
