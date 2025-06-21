package com.postprod.TrafficMirror.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.postprod.TrafficMirror.config.MirrorProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {
    
    private final MirrorProperties mirrorProperties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    public void logMirrorRequest(HttpServletRequest request, String developerId, 
                                String forwardUrl, String requestBody, 
                                boolean success, String errorMessage) {
        if (!mirrorProperties.getAudit().isEnabled()) {
            return;
        }
        
        try {
            Map<String, Object> auditEntry = createAuditEntry(
                request, developerId, forwardUrl, requestBody, success, errorMessage
            );
            
            String auditJson = objectMapper.writeValueAsString(auditEntry);
            
            // Log to application log
            logToApplicationLogs(auditJson);
            
            // Persist to audit log file if configured
            if (mirrorProperties.getAudit().isPersistAuditLogs()) {
                persistAuditLog(auditJson);
            }
            
        } catch (Exception e) {
            log.error("Failed to create audit log entry: {}", e.getMessage(), e);
        }
    }
    
    public void logSecurityViolation(HttpServletRequest request, String violationType, 
                                   String details, String developerId) {
        if (!mirrorProperties.getAudit().isEnabled()) {
            return;
        }
        
        try {
            Map<String, Object> securityEntry = new HashMap<>();
            securityEntry.put("timestamp", Instant.now().toString());
            securityEntry.put("eventType", "SECURITY_VIOLATION");
            securityEntry.put("violationType", violationType);
            securityEntry.put("details", details);
            securityEntry.put("developerId", developerId);
            securityEntry.put("clientIp", getClientIpAddress(request));
            securityEntry.put("userAgent", request.getHeader("User-Agent"));
            securityEntry.put("requestUri", request.getRequestURI());
            securityEntry.put("method", request.getMethod());
            
            String auditJson = objectMapper.writeValueAsString(securityEntry);
            
            // Always log security violations at WARN level
            log.warn("SECURITY_VIOLATION: {}", auditJson);
            
            if (mirrorProperties.getAudit().isPersistAuditLogs()) {
                persistAuditLog(auditJson);
            }
            
        } catch (Exception e) {
            log.error("Failed to log security violation: {}", e.getMessage(), e);
        }
    }
    
    public void logConfigurationChange(String configKey, String oldValue, 
                                     String newValue, String changedBy) {
        if (!mirrorProperties.getAudit().isEnabled()) {
            return;
        }
        
        try {
            Map<String, Object> configEntry = new HashMap<>();
            configEntry.put("timestamp", Instant.now().toString());
            configEntry.put("eventType", "CONFIGURATION_CHANGE");
            configEntry.put("configKey", configKey);
            configEntry.put("oldValue", maskSensitiveValue(configKey, oldValue));
            configEntry.put("newValue", maskSensitiveValue(configKey, newValue));
            configEntry.put("changedBy", changedBy);
            
            String auditJson = objectMapper.writeValueAsString(configEntry);
            
            log.info("CONFIGURATION_CHANGE: {}", auditJson);
            
            if (mirrorProperties.getAudit().isPersistAuditLogs()) {
                persistAuditLog(auditJson);
            }
            
        } catch (Exception e) {
            log.error("Failed to log configuration change: {}", e.getMessage(), e);
        }
    }
    
    private Map<String, Object> createAuditEntry(HttpServletRequest request, String developerId,
                                               String forwardUrl, String requestBody,
                                               boolean success, String errorMessage) {
        Map<String, Object> auditEntry = new HashMap<>();
        
        // Basic information
        auditEntry.put("timestamp", Instant.now().toString());
        auditEntry.put("eventType", "TRAFFIC_MIRROR");
        auditEntry.put("success", success);
        auditEntry.put("developerId", developerId);
        
        // Request information
        auditEntry.put("method", request.getMethod());
        auditEntry.put("requestUri", request.getRequestURI());
        auditEntry.put("forwardUrl", forwardUrl);
        auditEntry.put("clientIp", getClientIpAddress(request));
        auditEntry.put("userAgent", request.getHeader("User-Agent"));
        
        // Headers (filtered for sensitive information)
        if (mirrorProperties.getAudit().isLogHeaders()) {
            Map<String, String> headers = new HashMap<>();
            request.getHeaderNames().asIterator().forEachRemaining(headerName -> {
                if (!isSensitiveHeader(headerName)) {
                    headers.put(headerName, request.getHeader(headerName));
                } else {
                    headers.put(headerName, "***MASKED***");
                }
            });
            auditEntry.put("headers", headers);
        }
        
        // Request body (if configured to log)
        if (mirrorProperties.getAudit().isLogRequestBody() && requestBody != null) {
            auditEntry.put("requestBody", requestBody);
        }
        
        // Error information
        if (!success && errorMessage != null) {
            auditEntry.put("errorMessage", errorMessage);
        }
        
        // Session information
        if (request.getSession(false) != null) {
            auditEntry.put("sessionId", request.getSession().getId());
        }
        
        return auditEntry;
    }
    
    private void logToApplicationLogs(String auditJson) {
        String logLevel = mirrorProperties.getAudit().getAuditLogLevel().toUpperCase();
        
        switch (logLevel) {
            case "DEBUG":
                log.debug("AUDIT: {}", auditJson);
                break;
            case "INFO":
                log.info("AUDIT: {}", auditJson);
                break;
            case "WARN":
                log.warn("AUDIT: {}", auditJson);
                break;
            case "ERROR":
                log.error("AUDIT: {}", auditJson);
                break;
            default:
                log.info("AUDIT: {}", auditJson);
        }
    }
    
    private void persistAuditLog(String auditJson) {
        String auditLogPath = mirrorProperties.getAudit().getAuditLogPath();
        if (auditLogPath == null || auditLogPath.isEmpty()) {
            return;
        }
        
        try (FileWriter writer = new FileWriter(auditLogPath, true)) {
            writer.write(auditJson + System.lineSeparator());
            writer.flush();
        } catch (IOException e) {
            log.error("Failed to persist audit log to file {}: {}", auditLogPath, e.getMessage());
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
    
    private boolean isSensitiveHeader(String headerName) {
        if (headerName == null) {
            return false;
        }
        
        String lowerHeaderName = headerName.toLowerCase();
        return lowerHeaderName.contains("authorization") ||
               lowerHeaderName.contains("cookie") ||
               lowerHeaderName.contains("token") ||
               lowerHeaderName.contains("key") ||
               lowerHeaderName.contains("secret") ||
               lowerHeaderName.contains("password");
    }
    
    private String maskSensitiveValue(String configKey, String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        
        String lowerConfigKey = configKey.toLowerCase();
        if (lowerConfigKey.contains("secret") ||
            lowerConfigKey.contains("key") ||
            lowerConfigKey.contains("password") ||
            lowerConfigKey.contains("token")) {
            return "***MASKED***";
        }
        
        return value;
    }
} 