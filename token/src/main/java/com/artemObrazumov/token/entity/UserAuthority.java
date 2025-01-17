package com.artemObrazumov.token.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "authorities", uniqueConstraints = @UniqueConstraint(columnNames = {"id_user", "authority"}))
public class UserAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(targetEntity = UserEntity.class)
    @JoinColumn(name = "id_user", nullable = false)
    private UserEntity user;

    @Column(name = "authority", nullable = false)
    private String authority;

    public UserAuthority() {
    }

    public UserAuthority(Long id, UserEntity user, String authority) {
        this.id = id;
        this.user = user;
        this.authority = authority;
    }

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }
}
