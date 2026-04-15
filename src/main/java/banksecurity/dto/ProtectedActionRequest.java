package banksecurity.dto;

import banksecurity.model.ProtectedActionType;

public record ProtectedActionRequest(
        ProtectedActionType actionType
) {
}
