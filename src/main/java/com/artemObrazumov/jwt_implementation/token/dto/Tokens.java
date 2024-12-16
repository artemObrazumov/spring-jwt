package com.artemObrazumov.jwt_implementation.token.dto;

public record Tokens(String accessToken, String accessTokenExpireDate,
                     String refreshToken, String refreshTokenExpireDate) {
}
