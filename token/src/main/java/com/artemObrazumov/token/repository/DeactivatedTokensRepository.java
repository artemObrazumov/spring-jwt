package com.artemObrazumov.token.repository;

import com.artemObrazumov.token.entity.DeactivatedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface DeactivatedTokensRepository extends JpaRepository<DeactivatedToken, UUID> {

}
