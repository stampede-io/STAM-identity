package com.stampedeio.identity.domain;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, UUID> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    @Modifying
    @Query("UPDATE RefreshTokenEntity r SET r.revoked = true WHERE r.familyId = :familyId")
    int revokeByFamilyId(UUID familyId);

    @Modifying
    @Query("DELETE FROM RefreshTokenEntity r WHERE r.authorizationId = :authorizationId")
    void deleteByAuthorizationId(String authorizationId);
}
