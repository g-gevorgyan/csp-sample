package csp.sample;

import okhttp3.*;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Business logic.
 *
 * @author Garnik Gevorgyan (garnikg@vmware.com) on 11.07.23
 */
public class Main {
    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());
    private static final String AOA_GET_ALERTS_API = "<AOA_BASE_URL>/api/v2/alert?offset=0&limit=5";
    private static final String AOA_TENANT_ID = "<AOA_TENANT_ID>";

    private static final String CSP_API_TOKEN = "<CSP_API_TOKEN>";

    private static final String OAUTH_APP_ID = "<OAUTH_APP_ID>";
    private static final String OAUTH_APP_SECRET = "<OAUTH_APP_SECRET>";

    private static final OkHttpClient aoaClient = new OkHttpClient();


    public static void main(String[] args) throws InterruptedException {
        CSPTokensProvider tokensProvider = new CSPTokensProvider();

        while (true) {
            // Do your job, call WF API.
            CSPTokens userTokens = tokensProvider.getToken(CSP_API_TOKEN);
            printUserMessages(userTokens.getAccessToken());

            CSPTokens oauthAppTokens = tokensProvider.getToken(OAUTH_APP_ID, OAUTH_APP_SECRET, null);
            printUserMessages(oauthAppTokens.getAccessToken());

            // Do anything else
            Thread.sleep(TimeUnit.MINUTES.toMillis(10));
        }
    }

    private static void printUserMessages(@NotNull final String accessToken) {
        Request request = new Request.Builder().
                url(AOA_GET_ALERTS_API).
                header("Authorization", "Bearer " + accessToken).
                header("X-WAVEFRONT-TENANT", AOA_TENANT_ID).
                get().
                build();

        try (ResponseBody responseBody = aoaClient.newCall(request).execute().body()) {
            assert responseBody != null;
            LOGGER.info(responseBody.string());
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to get messages", e);
        }
    }
}

