package com.postprod.TrafficMirror.security;

import com.postprod.TrafficMirror.config.MirrorProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityValidationService {
    
    private final MirrorProperties mirrorProperties;
    private final Map<String, AtomicInteger> requestCountsPerMinute = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> requestCountsPerHour = new ConcurrentHashMap<>();
    private final Map<String, Long> lastResetTime = new ConcurrentHashMap<>();
    
    public boolean validateRequest(HttpServletRequest request, String forwardUrl, String developerId) {
        // Validate IP restrictions
        if (!validateIpRestrictions(request)) {
            log.warn("IP validation failed for request from: {}", getClientIpAddress(request));
            return false;
        }
        
        // Validate URL
        if (!validateForwardUrl(forwardUrl)) {
            log.warn("URL validation failed for: {}", forwardUrl);
            return false;
        }
        
        // Check rate limits
        if (!checkRateLimit(developerId)) {
            log.warn("Rate limit exceeded for developer: {}", developerId);
            return false;
        }
        
        return true;
    }
    
    private boolean validateIpRestrictions(HttpServletRequest request) {
        if (!mirrorProperties.getSecurity().isIpRestrictionEnabled()) {
            return true;
        }
        
        String clientIp = getClientIpAddress(request);
        Set<String> allowedIps = mirrorProperties.getSecurity().getAllowedIps();
        Set<String> allowedIpRanges = mirrorProperties.getSecurity().getAllowedIpRanges();
        
        // Check exact IP matches
        if (allowedIps != null && allowedIps.contains(clientIp)) {
            return true;
        }
        
        // Check IP ranges (CIDR notation)
        if (allowedIpRanges != null) {
            for (String range : allowedIpRanges) {
                if (isIpInRange(clientIp, range)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private boolean validateForwardUrl(String forwardUrl) {
        if (!mirrorProperties.getSecurity().isUrlValidationEnabled()) {
            return true;
        }
        
        try {
            URI uri = new URI(forwardUrl);
            
            // Validate protocol
            if (mirrorProperties.getSecurity().isRequireTls() && !"https".equals(uri.getScheme())) {
                log.warn("Non-HTTPS URL not allowed: {}", forwardUrl);
                return false;
            }
            
            // Validate domain
            Set<String> allowedDomains = mirrorProperties.getSecurity().getAllowedDomains();
            if (allowedDomains != null && !allowedDomains.isEmpty()) {
                String host = uri.getHost();
                boolean domainAllowed = allowedDomains.stream()
                        .anyMatch(domain -> host.equals(domain) || host.endsWith("." + domain));
                
                if (!domainAllowed) {
                    log.warn("Domain not allowed: {}", host);
                    return false;
                }
            }
            
            // Validate URL patterns
            Set<String> allowedPatterns = mirrorProperties.getSecurity().getAllowedUrlPatterns();
            if (allowedPatterns != null && !allowedPatterns.isEmpty()) {
                boolean patternMatched = allowedPatterns.stream()
                        .anyMatch(pattern -> Pattern.matches(pattern, forwardUrl));
                
                if (!patternMatched) {
                    log.warn("URL pattern not matched: {}", forwardUrl);
                    return false;
                }
            }
            
            return true;
            
        } catch (URISyntaxException e) {
            log.warn("Invalid URL format: {}", forwardUrl);
            return false;
        }
    }
    
    private boolean checkRateLimit(String developerId) {
        if (!mirrorProperties.getSecurity().isRateLimitingEnabled()) {
            return true;
        }
        
        long currentTime = System.currentTimeMillis();
        String key = developerId != null ? developerId : "anonymous";
        
        // Reset counters if needed
        resetCountersIfNeeded(key, currentTime);
        
        // Check per-minute limit
        AtomicInteger minuteCount = requestCountsPerMinute.computeIfAbsent(key, k -> new AtomicInteger(0));
        if (minuteCount.get() >= mirrorProperties.getSecurity().getMaxRequestsPerMinute()) {
            return false;
        }
        
        // Check per-hour limit
        AtomicInteger hourCount = requestCountsPerHour.computeIfAbsent(key, k -> new AtomicInteger(0));
        if (hourCount.get() >= mirrorProperties.getSecurity().getMaxRequestsPerHour()) {
            return false;
        }
        
        // Increment counters
        minuteCount.incrementAndGet();
        hourCount.incrementAndGet();
        
        return true;
    }
    
    private void resetCountersIfNeeded(String key, long currentTime) {
        Long lastReset = lastResetTime.get(key);
        if (lastReset == null || currentTime - lastReset > 60000) { // 1 minute
            requestCountsPerMinute.put(key, new AtomicInteger(0));
            if (lastReset == null || currentTime - lastReset > 3600000) { // 1 hour
                requestCountsPerHour.put(key, new AtomicInteger(0));
            }
            lastResetTime.put(key, currentTime);
        }
    }
    
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
    
    private boolean isIpInRange(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/");
            InetAddress targetAddr = InetAddress.getByName(ip);
            InetAddress rangeAddr = InetAddress.getByName(parts[0]);
            int prefixLength = Integer.parseInt(parts[1]);
            
            byte[] targetBytes = targetAddr.getAddress();
            byte[] rangeBytes = rangeAddr.getAddress();
            
            int bytesToCheck = prefixLength / 8;
            int bitsToCheck = prefixLength % 8;
            
            // Check full bytes
            for (int i = 0; i < bytesToCheck; i++) {
                if (targetBytes[i] != rangeBytes[i]) {
                    return false;
                }
            }
            
            // Check partial byte if needed
            if (bitsToCheck > 0 && bytesToCheck < targetBytes.length) {
                int mask = 0xFF << (8 - bitsToCheck);
                return (targetBytes[bytesToCheck] & mask) == (rangeBytes[bytesToCheck] & mask);
            }
            
            return true;
            
        } catch (UnknownHostException | NumberFormatException e) {
            log.warn("Invalid IP or CIDR format: {} / {}", ip, cidr);
            return false;
        }
    }
} 