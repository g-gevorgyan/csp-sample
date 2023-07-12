package csp.sample;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provider class to fetch, cache, update and provide CSP tokens.
 *
 * @author Garnik Gevorgyan (garnikg@vmware.com) on 11.07.23
 */
public class CSPTokensProvider {

    private static final Logger LOGGER = Logger.getLogger(CSPTokensProvider.class.getName());

    private static final String CSP_API_TOKEN_URL = "https://console-stg.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize";
    private static final String CSP_OAUTH_TOKEN_URL = "https://console-stg.cloud.vmware.com/csp/gateway/am/api/auth/authorize";

    private static final int clockSkew = 60;
    private static final int delayOnFail = 10;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final OkHttpClient cspClient = new OkHttpClient();

    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private final Map<String, CSPTokens> tokensCache = new ConcurrentHashMap<>();

    /**
     * Get access token by user's API token.
     *
     * @param apiToken User's API token
     * @return csp tokens or null if there are no tokens and getting a new one failed
     */
    public CSPTokens getToken(@NotNull String apiToken) {
        return tokensCache.computeIfAbsent(apiToken,
                key -> {
                    CSPTokens tokens = fetchTokens(apiToken);
                    int delay = tokens == null ? delayOnFail : tokens.getExpiresIn() - clockSkew;
                    scheduleTokenUpdate(apiToken, delay);
                    return tokens;
                });
    }

    /**
     * Get access token by OAuth app credentials.
     *
     * @param appId     OAuth app ID
     * @param appSecret OAuth app secret
     * @param orgId     CSP organization ID
     * @return csp tokens or null if there are no tokens and getting a new one failed
     */
    public CSPTokens getToken(@NotNull final String appId,
                              @NotNull final String appSecret,
                              @Nullable final String orgId) {
        return tokensCache.computeIfAbsent(appId,
                key -> {
                    CSPTokens tokens = fetchTokens(appId, appSecret, orgId);
                    int delay = tokens == null ? delayOnFail : tokens.getExpiresIn() - clockSkew;
                    scheduleTokenUpdate(appId, appSecret, orgId, delay);
                    return tokens;
                });
    }

    /**
     * Schedule a task to update access token for given API token.
     *
     * @param apiToken User's API token
     * @param delay    delay in seconds to run the task
     */
    private void scheduleTokenUpdate(@NotNull final String apiToken, final int delay) {
        executor.schedule(() -> {
            CSPTokens tokens = fetchTokens(apiToken);
            int dly = delayOnFail;
            if (tokens != null) {
                tokensCache.put(apiToken, tokens);
                dly = tokens.getExpiresIn() - clockSkew;
            }
            scheduleTokenUpdate(apiToken, dly);
        }, delay, TimeUnit.SECONDS);
    }

    /**
     * Schedule a task to update access token for given OAuth app credentials.
     *
     * @param appId     OAuth app ID
     * @param appSecret OAuth app secret
     * @param orgId     CSP organization ID
     * @param delay     delay in seconds to run the task
     */
    private void scheduleTokenUpdate(@NotNull final String appId,
                                     @NotNull final String appSecret,
                                     @Nullable final String orgId,
                                     final int delay) {
        executor.schedule(() -> {
            CSPTokens tokens = fetchTokens(appId, appSecret, orgId);
            int dly = delayOnFail;
            if (tokens != null) {
                tokensCache.put(appId, tokens);
                dly = tokens.getExpiresIn() - clockSkew;
            }
            scheduleTokenUpdate(appId, appSecret, orgId, dly);
        }, delay, TimeUnit.SECONDS);
    }

    /**
     * Method to get CSP access token using CSP API token.
     * <a href="https://console-stg.cloud.vmware.com/csp/gateway/authn/api/swagger-ui.html#/Authentication/getAccessTokenByApiRefreshTokenUsingPOST">...</a>
     *
     * @param apiToken user's API token
     * @return CSP tokens, or null if something failed
     */
    private CSPTokens fetchTokens(@NotNull final String apiToken) {
        LOGGER.info("Fetching tokens by API token");

        Request request = new Request.Builder().
                url(CSP_API_TOKEN_URL).
                post(new FormBody(List.of("api_token"), List.of(apiToken))).
                build();

        return requestTokens(request);
    }

    /**
     * Method to get CSP access token using CSP server-to-server OAuth app credentials.
     * <a href="https://console-stg.cloud.vmware.com/csp/gateway/authn/api/swagger-ui.html#/Authentication/getTokenForAuthGrantTypeInternalUsingPOST">...</a>
     *
     * @param appId     OAuth app ID
     * @param appSecret OAuth app secret
     * @param orgId     CSP org ID
     * @return CSP tokens, or null if something failed
     */
    private CSPTokens fetchTokens(@NotNull final String appId, @NotNull final String appSecret,
                                  @Nullable final String orgId) {
        LOGGER.info("Fetching tokens by by OAuth app credentials");

        String credentials = Credentials.basic(appId, appSecret);
        FormBody body = orgId == null ?
                new FormBody(List.of("grant_type"), List.of("client_credentials")) :
                new FormBody(List.of("grant_type", "orgId"), List.of("client_credentials", orgId));
        Request request = new Request.Builder().
                url(CSP_OAUTH_TOKEN_URL).
                post(body).
                header("Authorization", credentials).
                build();

        return requestTokens(request);
    }

    private CSPTokens requestTokens(@NotNull Request request) {
        try {
            Response response = cspClient.newCall(request).execute();
            ResponseBody responseBody = response.body();
            if (response.isSuccessful()) {
                assert responseBody != null;
                CSPTokens newTokens = objectMapper.readValue(responseBody.byteStream(), CSPTokens.class);
                responseBody.close();
                return newTokens;
            } else {
                LOGGER.log(Level.SEVERE, "Error to fetch CSP tokens: " + response.code());
                return null;
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error to fetch CSP tokens", e);
            return null;
        }
    }
}
