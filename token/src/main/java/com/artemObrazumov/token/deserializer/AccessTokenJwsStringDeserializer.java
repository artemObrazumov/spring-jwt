package com.artemObrazumov.token.deserializer;

import com.artemObrazumov.token.Token;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;

import java.util.UUID;
import java.util.function.Function;

public class AccessTokenJwsStringDeserializer implements Function<String, Token> {

    private final JWSVerifier jwsVerifier;

    public AccessTokenJwsStringDeserializer(JWSVerifier jwsVerifier) {
        this.jwsVerifier = jwsVerifier;
    }

    @Override
    public Token apply(String string) {
        try {
            var signedJWT = SignedJWT.parse(string);
            if (signedJWT.verify(this.jwsVerifier)) {
                var claimsSet = signedJWT.getJWTClaimsSet();
                return new Token(UUID.fromString(claimsSet.getJWTID()), claimsSet.getSubject(),
                        claimsSet.getStringListClaim("authorities"), claimsSet.getIssueTime().toInstant(),
                        claimsSet.getExpirationTime().toInstant());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

