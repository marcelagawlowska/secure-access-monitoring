package banksecurity.service;

import banksecurity.model.KnownDevice;
import banksecurity.model.KnownSource;
import banksecurity.repository.KnownDeviceRepository;
import banksecurity.repository.KnownSourceRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.UUID;

@Service
public class AccessContextService {

    public static final String DEVICE_COOKIE_NAME = "sam-device-id";
    private static final int DEVICE_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 180;

    private final KnownDeviceRepository knownDeviceRepository;
    private final KnownSourceRepository knownSourceRepository;

    public AccessContextService(KnownDeviceRepository knownDeviceRepository,
                                KnownSourceRepository knownSourceRepository) {
        this.knownDeviceRepository = knownDeviceRepository;
        this.knownSourceRepository = knownSourceRepository;
    }

    @Transactional(readOnly = true)
    public AccessContext resolve(String username,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {
        String normalizedUsername = requireText(username, "Username must not be blank");
        String source = resolveSource(request);
        String deviceId = resolveDeviceId(request, response);

        boolean userHasKnownDevices = knownDeviceRepository.existsByUsername(normalizedUsername);
        boolean userHasKnownSources = knownSourceRepository.existsByUsername(normalizedUsername);

        boolean newDevice = userHasKnownDevices
                && !knownDeviceRepository.existsByUsernameAndDeviceId(normalizedUsername, deviceId);
        boolean newSource = userHasKnownSources
                && !knownSourceRepository.existsByUsernameAndSourceValue(normalizedUsername, source);

        return new AccessContext(source, deviceId, newDevice, newSource);
    }

    @Transactional
    public void rememberTrustedContext(String username, AccessContext context) {
        String normalizedUsername = requireText(username, "Username must not be blank");
        LocalDateTime now = LocalDateTime.now();

        KnownDevice knownDevice = knownDeviceRepository.findByUsernameAndDeviceId(normalizedUsername, context.deviceId())
                .orElseGet(KnownDevice::new);
        if (knownDevice.getId() == null) {
            knownDevice.setUsername(normalizedUsername);
            knownDevice.setDeviceId(context.deviceId());
            knownDevice.setFirstSeenAt(now);
        }
        knownDevice.setLastSeenAt(now);
        knownDeviceRepository.save(knownDevice);

        KnownSource knownSource = knownSourceRepository.findByUsernameAndSourceValue(normalizedUsername, context.source())
                .orElseGet(KnownSource::new);
        if (knownSource.getId() == null) {
            knownSource.setUsername(normalizedUsername);
            knownSource.setSourceValue(context.source());
            knownSource.setFirstSeenAt(now);
        }
        knownSource.setLastSeenAt(now);
        knownSourceRepository.save(knownSource);
    }

    public String resolveSource(HttpServletRequest request) {
        String forwardedFor = normalizeValue(request.getHeader("X-Forwarded-For"));
        if (forwardedFor != null) {
            return forwardedFor.split(",")[0].trim();
        }

        String realIp = normalizeValue(request.getHeader("X-Real-IP"));
        if (realIp != null) {
            return realIp;
        }

        String remoteAddress = request.getRemoteAddr();
        return remoteAddress == null || remoteAddress.isBlank() ? "unknown" : remoteAddress.trim();
    }

    private String resolveDeviceId(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            String existingDeviceId = Arrays.stream(cookies)
                    .filter(cookie -> DEVICE_COOKIE_NAME.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .map(this::normalizeValue)
                    .filter(value -> value != null)
                    .findFirst()
                    .orElse(null);
            if (existingDeviceId != null) {
                return existingDeviceId;
            }
        }

        String generatedDeviceId = UUID.randomUUID().toString();
        Cookie cookie = new Cookie(DEVICE_COOKIE_NAME, generatedDeviceId);
        cookie.setPath("/");
        cookie.setMaxAge(DEVICE_COOKIE_MAX_AGE_SECONDS);
        cookie.setHttpOnly(false);
        response.addCookie(cookie);
        return generatedDeviceId;
    }

    private String requireText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(message);
        }
        return value.trim();
    }

    private String normalizeValue(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
