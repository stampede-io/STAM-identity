package com.stampedeio.identity.api.dto;

import jakarta.validation.constraints.NotNull;

import com.stampedeio.identity.domain.Role;

public record RoleChangeRequest(
        @NotNull Role role
) {}
