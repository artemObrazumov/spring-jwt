package com.artemObrazumov.token.entity;

import jakarta.persistence.*;

import java.util.Date;
import java.util.UUID;

@Entity
@Table(name = "deactivated_tokens")
public class DeactivatedToken {

    @Id
    private UUID id;

    @Column(name = "keep_until", nullable = false)
    private Date keepUntil;

    public DeactivatedToken() {
    }

    public DeactivatedToken(UUID id, Date keepUntil) {
        this.id = id;
        this.keepUntil = keepUntil;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Date getKeepUntil() {
        return keepUntil;
    }

    public void setKeepUntil(Date keepUntil) {
        this.keepUntil = keepUntil;
    }
}
