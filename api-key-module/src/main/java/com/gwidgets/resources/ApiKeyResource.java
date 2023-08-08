package com.gwidgets.resources;

import com.google.common.base.Strings;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import org.jboss.logging.Logger;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.PathSegment;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class ApiKeyResource {
    private static final Logger logger = Logger.getLogger(ApiKeyResource.class);
    private static final String AUTH_METHOD = "X-API-KEY";
    private static final String HDR_USER_ID = "X-User-Id";
    private static final String INVALID_API_KEY = "INVALID_API_KEY";
    private static final String PERMISSION_DENIED = "PERMISSION_DENIED";

    private KeycloakSession session;

    private final String realmName;
    private final String clientId;
    private final String allAccessGroupName;
    private RealmModel actualRealm;

    public ApiKeyResource(KeycloakSession session) {
        this.session = session;
        String envRealmName = System.getenv("X_API_CHECK_REALM");
        this.actualRealm = this.session.getContext().getRealm();
        this.realmName = Objects.isNull(envRealmName) || Objects.equals(System.getenv(envRealmName), "") ? "example" : envRealmName;
        this.clientId = System.getenv("X_API_CHECK_CLIENT_ID");
        this.allAccessGroupName = System.getenv("X_API_ALL_ACCESS_GROUP");
    }

    @GET
    @Produces("application/json")
    public Response checkApiKey(@Context UriInfo uriInfo, @QueryParam("apiKey") String apiKey, @QueryParam("memberOf") String groupName) {
        Response.Status status = Response.Status.UNAUTHORIZED;
        RealmModel realm;
        if (this.actualRealm != null) {
            realm = this.actualRealm;
            logger.info("The actual realm is from the session");
        } else {
            String forRealzRealmName;
            List<PathSegment> segments = uriInfo.getPathSegments();
            int wow = -1;
            for (int i=0; i<segments.size();i++) {
                if (segments.get(i).getPath() == "realms") {
                    wow = i+1;
                }
            }
            if (wow >= 0) {
                String uriRealmName = uriInfo.getPathSegments().get(wow).getPath();
                forRealzRealmName = uriRealmName;
                logger.info("The actual realm is from the uri info");
            } else {
                forRealzRealmName = this.realmName;
                logger.info("The actual realm is from the env var");
            }
            logger.info("and this is the realm name: " + forRealzRealmName);
            realm = session.realms().getRealm(forRealzRealmName);
        }
        logger.info("and this is the realm name: " + realm.getName());
        UserModel user = null;
        EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());

        event.event(EventType.LOGIN);
        event.detail(Details.AUTH_METHOD, AUTH_METHOD);
        if (null == this.clientId || "%user_id%".equals(this.clientId)) {
            event.client(session.getContext().getClient());
        } else if ("%api_key%".equals(this.clientId)) {
            event.client(apiKey);
        } else {
            event.client(this.clientId);
        }

        List<UserModel> matches = session.users()
                .searchForUserByUserAttributeStream(realm, "api-key", apiKey)
                .filter(UserModel::isEnabled)
                .collect(Collectors.toList());

        if (matches.size() == 1) {
            UserModel candidate = matches.get(0);

            if (Strings.isNullOrEmpty(groupName) ||
                    isMemberOf(realm, candidate, groupName) ||
                    (!Strings.isNullOrEmpty(allAccessGroupName) && isMemberOf(realm, candidate, allAccessGroupName))) {
                user = candidate;
                event.user(user);
                if ("%user_id%".equals(this.clientId)) {
                    event.client(user.getId());
                }
                event.success();
                status = Response.Status.OK;
            } else {
                event.error(PERMISSION_DENIED);
            }
        } else {
            event.error(INVALID_API_KEY);
        }

        Response.ResponseBuilder builder = Response.status(status).type(MediaType.APPLICATION_JSON);
        if (null != user) {
            builder = builder.header(HDR_USER_ID, user.getId());
            Map<String, List<String>> attribs = user.getAttributes();
            for (String key : attribs.keySet()) {
                if (key.toLowerCase().startsWith("x-")) {
                    List<String> values = attribs.get(key);
                    if (null != values && !values.isEmpty()) {
                        builder = builder.header(key, values.get(0));
                    }
                }
            }
        }

        return builder.build();
    }

    private boolean isMemberOf(RealmModel realm, UserModel user, String groupName) {
        return !session.groups()
                .getGroupsStream(realm)
                .filter(g -> g.getName().equalsIgnoreCase(groupName))
                .filter(user::isMemberOf)
                .collect(Collectors.toList())
                .isEmpty();
    }
}
