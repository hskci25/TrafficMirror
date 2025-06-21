package com.postprod.TrafficMirror.security;

import com.postprod.TrafficMirror.config.MirrorProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtAuthenticationService {
    
    private final MirrorProperties mirrorProperties;
    
    public boolean validateToken(String token) {
        if (!mirrorProperties.getSecurity().isJwtEnabled()) {
            return true; // JWT disabled, skip validation
        }
        
        try {
            Claims claims = parseToken(token);
            
            // Validate expiration
            if (claims.getExpiration().before(new Date())) {
                log.warn("JWT token expired");
                return false;
            }
            
            // Validate issuer
            String expectedIssuer = mirrorProperties.getSecurity().getJwtIssuer();
            if (!expectedIssuer.equals(claims.getIssuer())) {
                log.warn("Invalid JWT issuer: expected {}, got {}", expectedIssuer, claims.getIssuer());
                return false;
            }
            
            // Validate developer authorization
            if (mirrorProperties.getSecurity().isRequireDeveloperAuth()) {
                String developerId = claims.getSubject();
                Set<String> authorizedDevelopers = mirrorProperties.getSecurity().getAuthorizedDevelopers();
                
                if (authorizedDevelopers != null && !authorizedDevelopers.contains(developerId)) {
                    log.warn("Unauthorized developer: {}", developerId);
                    return false;
                }
            }
            
            return true;
            
        } catch (JwtException e) {
            log.error("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    public String extractDeveloperId(String token) {
        try {
            Claims claims = parseToken(token);
            return claims.getSubject();
        } catch (JwtException e) {
            log.error("Failed to extract developer ID from token: {}", e.getMessage());
            return null;
        }
    }
    
    public String generateToken(String developerId) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + mirrorProperties.getSecurity().getJwtExpirationMs());
        
        return Jwts.builder()
                .setSubject(developerId)
                .setIssuer(mirrorProperties.getSecurity().getJwtIssuer())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(getSigningKey())
                .compact();
    }
    
    private Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    
    private SecretKey getSigningKey() {
        String secret = mirrorProperties.getSecurity().getJwtSecret();
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("JWT secret not configured");
        }
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
} 