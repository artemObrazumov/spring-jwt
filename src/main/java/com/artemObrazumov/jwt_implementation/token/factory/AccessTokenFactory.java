package com.artemObrazumov.jwt_implementation.token.factory;

import com.artemObrazumov.jwt_implementation.token.Token;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

public class AccessTokenFactory implements Function<Token, Token> {

    private Duration tokenLiveTime = Duration.ofMinutes(5);

    @Override
    public Token apply(Token token) {
        var authorities = token.authorities()
                .stream()
                .filter(authority -> authority.startsWith("GRANT_"))
                .map(authority -> authority.replaceFirst("GRANT_", ""))
                .toList();

        var createdAt = Instant.now();
        var expiresAt = createdAt.plus(tokenLiveTime);
        return new Token(token.id(), token.subject(), authorities, createdAt, expiresAt);
    }

    public void setTokenLiveTime(Duration tokenLiveTime) {
        this.tokenLiveTime = tokenLiveTime;
    }
}
