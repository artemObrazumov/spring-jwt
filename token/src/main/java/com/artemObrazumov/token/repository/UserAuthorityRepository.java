package com.artemObrazumov.token.repository;

import com.artemObrazumov.token.entity.UserAuthority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserAuthorityRepository extends JpaRepository<UserAuthority, UUID> {

    List<UserAuthority> findByUserId(Long id);
}
