package com.artemObrazumov.jwt_implementation.token.repository;

import com.artemObrazumov.jwt_implementation.token.entity.DeactivatedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface DeactivatedTokensRepository extends JpaRepository<DeactivatedToken, UUID> {

}
