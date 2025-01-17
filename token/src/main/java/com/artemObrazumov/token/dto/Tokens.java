package com.artemObrazumov.token.dto;

public record Tokens(String accessToken, String accessTokenExpireDate,
                     String refreshToken, String refreshTokenExpireDate) {
}
