package com.artemObrazumov.jwt_implementation.token.serializer;

import com.artemObrazumov.jwt_implementation.token.Token;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.sql.Date;
import java.util.function.Function;

public class AccessTokenJwsStringSerializer implements Function<Token, String> {

    private final JWSSigner jwsSigner;

    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner) {
        this.jwsSigner = jwsSigner;
    }

    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner, JWSAlgorithm jwsAlgorithm) {
        this.jwsSigner = jwsSigner;
        this.jwsAlgorithm = jwsAlgorithm;
    }

    @Override
    public String apply(Token token) {
        var jwsHeader = new JWSHeader.Builder(this.jwsAlgorithm)
                .keyID(token.id().toString())
                .build();
        var claimsSet = new JWTClaimsSet.Builder()
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet);
        try {
            signedJWT.sign(this.jwsSigner);
            return signedJWT.serialize();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void setJwsAlgorithm(JWSAlgorithm jwsAlgorithm) {
        this.jwsAlgorithm = jwsAlgorithm;
    }
}

