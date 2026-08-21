package com.stampedeio.identity.api.dto;

import java.util.UUID;

public record UserResponse(UUID id, String email, String role) {}
