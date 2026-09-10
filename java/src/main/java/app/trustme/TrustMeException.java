package app.trustme;

/** Thrown when a key file cannot be read or a secret cannot be fetched. */
public class TrustMeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public TrustMeException(String message) {
        super(message);
    }

    public TrustMeException(String message, Throwable cause) {
        super(message, cause);
    }
}
