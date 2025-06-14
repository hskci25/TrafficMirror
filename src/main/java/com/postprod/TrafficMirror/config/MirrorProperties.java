package com.postprod.TrafficMirror.config;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

@Data
@Validated
@ConfigurationProperties(prefix = "traffic-mirror")
public class MirrorProperties {
    private boolean enabled = false;
    
    @NotNull(message = "forward-url must be specified when traffic-mirror is enabled")
    private String forwardUrl;
    
    @NotEmpty(message = "At least one path-pattern must be specified when traffic-mirror is enabled")
    private List<String> pathPatterns;
    
    private Map<String, String> headers;
}
