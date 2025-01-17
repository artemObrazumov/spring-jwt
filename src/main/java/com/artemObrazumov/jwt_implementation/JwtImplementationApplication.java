package com.artemObrazumov.jwt_implementation;

import com.artemObrazumov.token.entity.UserAuthority;
import com.artemObrazumov.token.entity.UserEntity;
import com.artemObrazumov.token.repository.UserAuthorityRepository;
import com.artemObrazumov.token.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableWebSecurity(debug = true)
@SpringBootApplication
@ComponentScan(basePackages = {"com.artemObrazumov.*"})
public class JwtImplementationApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtImplementationApplication.class, args);
	}

	@Bean
	public CommandLineRunner addSampleUserWithAuthorities(
			UserRepository userRepository,
			UserAuthorityRepository userAuthorityRepository
	) {
		return args -> {
			var user = userRepository.save(new UserEntity(null, "j.jameson", "{noop}password"));
			userAuthorityRepository.save(new UserAuthority(null, user, "ROLE_MANAGER"));
		};
	}
}
