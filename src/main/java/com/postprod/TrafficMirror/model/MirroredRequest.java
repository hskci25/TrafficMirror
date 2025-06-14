package com.postprod.TrafficMirror.model;

import lombok.Builder;
import lombok.Data;
import java.time.Instant;
import java.util.Map;

@Data
@Builder
public class MirroredRequest {
    private String method;
    private String path;
    private Map<String, String> headers;
    private String body;
    private Instant timestamp;
}
