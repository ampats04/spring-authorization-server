package com.company.authserver.model;

import jakarta.validation.constraints.NotBlank;

public record TokenRequest(
        @NotBlank(message = "client_id is required") String clientId,
        @NotBlank(message = "client_secret is required") String clientSecret,
        @NotBlank(message = "account_number is required") String accountNumber
) {}
