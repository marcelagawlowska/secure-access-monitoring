package banksecurity.service;

public record AuthenticationFailureResult(
        boolean knownUser,
        boolean blocked
) {
}
