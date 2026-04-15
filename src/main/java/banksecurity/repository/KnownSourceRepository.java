package banksecurity.repository;

import banksecurity.model.KnownSource;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KnownSourceRepository extends JpaRepository<KnownSource, Long> {
    boolean existsByUsername(String username);

    boolean existsByUsernameAndSourceValue(String username, String sourceValue);

    Optional<KnownSource> findByUsernameAndSourceValue(String username, String sourceValue);
}
