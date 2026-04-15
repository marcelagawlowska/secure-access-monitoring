package banksecurity.repository;

import banksecurity.model.KnownDevice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KnownDeviceRepository extends JpaRepository<KnownDevice, Long> {
    boolean existsByUsername(String username);

    boolean existsByUsernameAndDeviceId(String username, String deviceId);

    Optional<KnownDevice> findByUsernameAndDeviceId(String username, String deviceId);
}
