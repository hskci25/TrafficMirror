package com.postprod.TrafficMirror.config;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
@Validated
@ConfigurationProperties(prefix = "traffic-mirror")
public class MirrorProperties {
    private boolean enabled = false;
    
    // Optional global forward URL - can be overridden by X-Mirror-Forward-URL header
    private String forwardUrl;
    
    @NotEmpty(message = "At least one path-pattern must be specified when traffic-mirror is enabled")
    private List<String> pathPatterns;
    
    private List<String> excludedPaths;
    
    private Map<String, String> headers;
    
    // Security Configuration
    private SecurityConfig security = new SecurityConfig();
    
    // Audit Configuration
    private AuditConfig audit = new AuditConfig();
    
    // Data Protection Configuration
    private DataProtectionConfig dataProtection = new DataProtectionConfig();
    
    @Data
    public static class SecurityConfig {
        // JWT Authentication
        private boolean jwtEnabled = true;
        private String jwtSecret;
        private long jwtExpirationMs = 3600000; // 1 hour
        private String jwtIssuer = "traffic-mirror";
        
        // IP Restrictions
        private boolean ipRestrictionEnabled = true;
        private Set<String> allowedIpRanges;
        private Set<String> allowedIps;
        
        // URL Validation
        private boolean urlValidationEnabled = true;
        private Set<String> allowedDomains;
        private Set<String> allowedUrlPatterns;
        
        // Rate Limiting
        private boolean rateLimitingEnabled = true;
        private int maxRequestsPerMinute = 10;
        private int maxRequestsPerHour = 100;
        
        // Developer Authentication
        private Set<String> authorizedDevelopers;
        private boolean requireDeveloperAuth = true;
        
        // TLS Configuration
        private boolean requireTls = true;
        private boolean validateCertificates = true;
        private Set<String> trustedCertificateFingerprints;
    }
    
    @Data
    public static class AuditConfig {
        private boolean enabled = true;
        private boolean logRequestBody = false; // Security: don't log sensitive data by default
        private boolean logResponseBody = false;
        private boolean logHeaders = true;
        private String auditLogLevel = "INFO";
        private boolean persistAuditLogs = true;
        private String auditLogPath = "/var/log/traffic-mirror/audit.log";
    }
    
    @Data
    public static class DataProtectionConfig {
        private boolean enabled = true;
        private boolean maskPii = true;
        private Set<String> piiFields = Set.of("ssn", "email", "phone", "creditCard", "password");
        private Set<String> sensitiveHeaders = Set.of("Authorization", "Cookie", "X-API-Key");
        private boolean encryptForwardedData = true;
        private String encryptionKey;
        private int dataRetentionDays = 7;
    }
}
