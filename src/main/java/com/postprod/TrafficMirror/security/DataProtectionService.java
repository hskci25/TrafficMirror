package com.postprod.TrafficMirror.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.postprod.TrafficMirror.config.MirrorProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class DataProtectionService {
    
    private final MirrorProperties mirrorProperties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    // Common PII patterns
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
    );
    private static final Pattern PHONE_PATTERN = Pattern.compile(
        "\\b(?:\\+?1[-.]?)?\\(?([0-9]{3})\\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\\b"
    );
    private static final Pattern SSN_PATTERN = Pattern.compile(
        "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    );
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile(
        "\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b"
    );
    
    public String sanitizeRequestBody(String requestBody) {
        if (!mirrorProperties.getDataProtection().isEnabled()) {
            return requestBody;
        }
        
        try {
            if (requestBody == null || requestBody.trim().isEmpty()) {
                return requestBody;
            }
            
            // Try to parse as JSON first
            if (requestBody.trim().startsWith("{") || requestBody.trim().startsWith("[")) {
                return sanitizeJsonData(requestBody);
            } else {
                // Handle as plain text
                return sanitizeTextData(requestBody);
            }
            
        } catch (Exception e) {
            log.warn("Failed to sanitize request body: {}", e.getMessage());
            return requestBody; // Return original if sanitization fails
        }
    }
    
    public Map<String, String> sanitizeHeaders(Map<String, String> headers) {
        if (!mirrorProperties.getDataProtection().isEnabled()) {
            return headers;
        }
        
        Set<String> sensitiveHeaders = mirrorProperties.getDataProtection().getSensitiveHeaders();
        if (sensitiveHeaders == null || sensitiveHeaders.isEmpty()) {
            return headers;
        }
        
        return headers.entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(
                    Map.Entry::getKey,
                    entry -> sensitiveHeaders.contains(entry.getKey().toLowerCase()) ? 
                        maskValue(entry.getValue()) : entry.getValue()
                ));
    }
    
    public String encryptData(String data) {
        if (!mirrorProperties.getDataProtection().isEncryptForwardedData()) {
            return data;
        }
        
        try {
            String encryptionKey = mirrorProperties.getDataProtection().getEncryptionKey();
            if (encryptionKey == null || encryptionKey.isEmpty()) {
                log.warn("Encryption key not configured, skipping encryption");
                return data;
            }
            
            SecretKey secretKey = new SecretKeySpec(
                encryptionKey.getBytes(StandardCharsets.UTF_8), "AES"
            );
            
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedData);
            
        } catch (Exception e) {
            log.error("Failed to encrypt data: {}", e.getMessage());
            return data; // Return original if encryption fails
        }
    }
    
    public String decryptData(String encryptedData) {
        if (!mirrorProperties.getDataProtection().isEncryptForwardedData()) {
            return encryptedData;
        }
        
        try {
            String encryptionKey = mirrorProperties.getDataProtection().getEncryptionKey();
            if (encryptionKey == null || encryptionKey.isEmpty()) {
                return encryptedData;
            }
            
            SecretKey secretKey = new SecretKeySpec(
                encryptionKey.getBytes(StandardCharsets.UTF_8), "AES"
            );
            
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            
            byte[] decodedData = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedData = cipher.doFinal(decodedData);
            
            return new String(decryptedData, StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            log.error("Failed to decrypt data: {}", e.getMessage());
            return encryptedData; // Return original if decryption fails
        }
    }
    
    private String sanitizeJsonData(String jsonData) {
        try {
            JsonNode rootNode = objectMapper.readTree(jsonData);
            JsonNode sanitizedNode = sanitizeJsonNode(rootNode);
            return objectMapper.writeValueAsString(sanitizedNode);
            
        } catch (Exception e) {
            log.warn("Failed to parse JSON for sanitization: {}", e.getMessage());
            return sanitizeTextData(jsonData);
        }
    }
    
    private JsonNode sanitizeJsonNode(JsonNode node) {
        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            Set<String> piiFields = mirrorProperties.getDataProtection().getPiiFields();
            
            objectNode.fields().forEachRemaining(entry -> {
                String fieldName = entry.getKey().toLowerCase();
                JsonNode fieldValue = entry.getValue();
                
                if (piiFields != null && piiFields.contains(fieldName)) {
                    objectNode.put(entry.getKey(), maskValue(fieldValue.asText()));
                } else if (fieldValue.isTextual()) {
                    String textValue = fieldValue.asText();
                    String sanitizedValue = sanitizeTextData(textValue);
                    if (!textValue.equals(sanitizedValue)) {
                        objectNode.put(entry.getKey(), sanitizedValue);
                    }
                } else if (fieldValue.isObject() || fieldValue.isArray()) {
                    objectNode.set(entry.getKey(), sanitizeJsonNode(fieldValue));
                }
            });
            
            return objectNode;
            
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                JsonNode arrayElement = node.get(i);
                if (arrayElement.isObject() || arrayElement.isArray()) {
                    ((com.fasterxml.jackson.databind.node.ArrayNode) node)
                        .set(i, sanitizeJsonNode(arrayElement));
                } else if (arrayElement.isTextual()) {
                    String textValue = arrayElement.asText();
                    String sanitizedValue = sanitizeTextData(textValue);
                    if (!textValue.equals(sanitizedValue)) {
                        ((com.fasterxml.jackson.databind.node.ArrayNode) node)
                            .set(i, objectMapper.valueToTree(sanitizedValue));
                    }
                }
            }
            return node;
        }
        
        return node;
    }
    
    private String sanitizeTextData(String text) {
        if (!mirrorProperties.getDataProtection().isMaskPii()) {
            return text;
        }
        
        String sanitized = text;
        
        // Mask email addresses
        sanitized = EMAIL_PATTERN.matcher(sanitized).replaceAll("***@***.***");
        
        // Mask phone numbers
        sanitized = PHONE_PATTERN.matcher(sanitized).replaceAll("***-***-****");
        
        // Mask SSNs
        sanitized = SSN_PATTERN.matcher(sanitized).replaceAll("***-**-****");
        
        // Mask credit card numbers
        sanitized = CREDIT_CARD_PATTERN.matcher(sanitized).replaceAll("****-****-****-****");
        
        return sanitized;
    }
    
    private String maskValue(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        
        if (value.length() <= 4) {
            return "*".repeat(value.length());
        }
        
        // Show first 2 and last 2 characters, mask the rest
        return value.substring(0, 2) + "*".repeat(value.length() - 4) + value.substring(value.length() - 2);
    }
    
    public static String generateEncryptionKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate encryption key", e);
        }
    }
} 