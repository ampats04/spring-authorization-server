package com.company.authserver.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ErrorResponse(
        String error,
        @JsonProperty("error_description") String errorDescription
) {}
