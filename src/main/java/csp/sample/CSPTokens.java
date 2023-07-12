package csp.sample;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

/**
 * Data class for CSP tokens.
 *
 * @author Garnik Gevorgyan (garnikg@vmware.com) on 11.07.23
 */

@Getter
public class CSPTokens {
    @JsonProperty("id_token")
    private String idToken;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expires_in")
    private int expiresIn;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;
}
