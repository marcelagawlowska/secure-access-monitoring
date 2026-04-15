package banksecurity.service;

public record AccessContext(
        String source,
        String deviceId,
        boolean newDevice,
        boolean newSource
) {
}
