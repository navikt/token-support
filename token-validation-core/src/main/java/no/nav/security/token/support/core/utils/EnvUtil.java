package no.nav.security.token.support.core.utils;

public
class EnvUtil {

    private
    EnvUtil() {

    }

    static final String FSS = "fss";
    static final String SBS = "sbs";
    static final String LOCAL = "local";
    static final String GCP = "gcp";
    static final String TEST = "test";
    static final String DEV = "dev";
    static final String PROD = "prod";
    static final String DEV_GCP = join(DEV, GCP);
    static final String PROD_GCP = join(PROD, GCP);
    static final String PROD_SBS = join(PROD, SBS);
    static final String DEV_SBS = join(DEV, SBS);
    static final String PROD_FSS = join(PROD, FSS);
    static final String DEV_FSS = join(DEV, FSS);
    static final String NAIS_CLUSTER_NAME = "NAIS_CLUSTER_NAME";

    private static String join(String env, String cluster) {
        return env + "-" + cluster;
    }

}