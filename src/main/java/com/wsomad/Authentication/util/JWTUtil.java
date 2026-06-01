package com.wsomad.Authentication.util;

import com.wsomad.Authentication.model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JWTUtil {
    private final String secret = "secret-key-help-to-secure-my-data-and-ease-my-work";
    private final Key key = Keys.hmacShaKeyFor(secret.getBytes());

    // Generate token
    // JWT always has 3 parts: {header.payload.signature}
    // 1- Header is signed with HMAC SHA
    // 2- Payload always contains subject (can be anything) + issued time + expiration time
    // 3- Signature is done by HMAC SHA
    public String generateToken(User user) {
        // So, we add more infos to let the authentication be more secure
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("role", user.getRole());

        return Jwts.builder()
                .subject(String.valueOf(user.getUserId())) // This is the primary part
                .claims(claims) // This is additional part
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(key)
                .compact();
    }

    public String extractToken(HttpServletRequest request) {
        String authenticationHeader = request.getHeader("Authorization");

        if (authenticationHeader == null || !authenticationHeader.startsWith("Bearer ")) {
            throw  new RuntimeException("Missing or invalid Authorization header");
        }

        return authenticationHeader.substring(7);
    }

    // Extract subject
    public Long extractSubject(String token) {
        Claims claim = parseClaims(token);
        return Long.parseLong(claim.getSubject());
    }

    // Validate token
    public boolean validateToken(String token) {
        return parseClaims(token) != null;
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
