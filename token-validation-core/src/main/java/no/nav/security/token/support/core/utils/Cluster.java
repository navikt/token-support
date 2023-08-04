package no.nav.security.token.support.core.utils;

import java.util.Objects;

import static java.lang.System.*;
import static no.nav.security.token.support.core.utils.EnvUtil.NAIS_CLUSTER_NAME;

public enum Cluster {
    TEST(EnvUtil.TEST),
    LOCAL(EnvUtil.LOCAL),
    DEV_SBS(EnvUtil.DEV_SBS),
    DEV_FSS(EnvUtil.DEV_FSS),
    DEV_GCP(EnvUtil.DEV_GCP),
    PROD_GCP(EnvUtil.PROD_GCP),
    PROD_FSS(EnvUtil.PROD_FSS),
    PROD_SBS(EnvUtil.PROD_SBS);
    private final String navn;

    public static Cluster currentCluster() {
        String current = cluster();
        for (Cluster cluster : values()) {
            if (Objects.equals(cluster.navn,current)) {
                return cluster;
            }
        }
        return LOCAL;
    }

    public static boolean isProd() {
        String current = cluster();
        return Objects.equals(current, EnvUtil.PROD_GCP) || Objects.equals(current, EnvUtil.PROD_FSS);

    }
    private static String  cluster() {
        return getenv(NAIS_CLUSTER_NAME);
    }

    Cluster(String navn) {
         this.navn = navn;
    }
}