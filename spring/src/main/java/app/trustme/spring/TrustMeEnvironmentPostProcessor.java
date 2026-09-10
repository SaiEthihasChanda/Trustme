package app.trustme.spring;

import app.trustme.TrustMe;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;

/**
 * Lets application.properties refer to TrustMe secrets directly:
 *
 * <pre>
 * trustme.key-file=C:/Users/you/.trustme/billing.TM
 *
 * jwt.secret=${trustme.secret.JWT_SECRET}
 * spring.datasource.password=${trustme.secret.DB_PASSWORD}
 * </pre>
 *
 * <p>Secrets are fetched lazily, so only the ones actually referenced cost a
 * round trip. The key file is unlocked once, on the first reference.
 *
 * <p>This runs before any bean is created, which is what makes it usable for
 * values that constructor injection needs. It also means the password prompt,
 * if one is needed, appears before the Spring banner.
 */
public class TrustMeEnvironmentPostProcessor implements EnvironmentPostProcessor {

    /** Properties under this prefix are resolved as secret names. */
    public static final String SECRET_PREFIX = "trustme.secret.";

    /** Optional path to the .TM file; otherwise the library's own discovery applies. */
    public static final String KEY_FILE_PROPERTY = "trustme.key-file";

    /** Set false to leave the environment untouched. */
    public static final String ENABLED_PROPERTY = "trustme.enabled";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (!environment.getProperty(ENABLED_PROPERTY, Boolean.class, Boolean.TRUE)) {
            return;
        }

        // Read configuration before the secret source is installed, so these
        // never route back into TrustMe as if they were secret names.
        String keyFile = environment.getProperty(KEY_FILE_PROPERTY);
        if (keyFile != null && !keyFile.isBlank()) {
            TrustMe.useKeyFile(keyFile.trim());
        }

        environment.getPropertySources().addLast(new SecretSource());
    }

    /**
     * Resolves one secret per lookup. Added last, so anything already defined in
     * application.properties or the environment still wins.
     */
    private static final class SecretSource extends PropertySource<Object> {

        SecretSource() {
            super("trustme-secrets", new Object());
        }

        @Override
        public Object getProperty(String name) {
            if (name == null || !name.startsWith(SECRET_PREFIX)) return null;
            String secretName = name.substring(SECRET_PREFIX.length());
            if (secretName.isEmpty()) return null;
            return TrustMe.get(secretName);
        }
    }
}
