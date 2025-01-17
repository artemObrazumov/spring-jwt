package com.artemObrazumov.token.deserializer;

import com.artemObrazumov.token.Token;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import java.util.UUID;
import java.util.function.Function;

public class RefreshTokenJwsStringDeserializer implements Function<String, Token> {

    private final JWEDecrypter jweDecrypter;

    public RefreshTokenJwsStringDeserializer(JWEDecrypter jweDecrypter) {
        this.jweDecrypter = jweDecrypter;
    }

    @Override
    public Token apply(String string) {
        try {
            var decryptedJWT = EncryptedJWT.parse(string);
            decryptedJWT.decrypt(jweDecrypter);
            var claimsSet = decryptedJWT.getJWTClaimsSet();
            return new Token(UUID.fromString(claimsSet.getJWTID()), claimsSet.getSubject(),
                    claimsSet.getStringListClaim("authorities"), claimsSet.getIssueTime().toInstant(),
                    claimsSet.getExpirationTime().toInstant());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
