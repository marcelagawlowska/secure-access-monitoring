package banksecurity.dto;

public record RegisteredUserResponse(
        Long id,
        String username,
        String role
) {
}
