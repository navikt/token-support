package no.nav.security.token.support.core.utils;

public class EnvUtil {

    private EnvUtil()  {

    }
     static  String  FSS = "fss";
     static  String SBS = "sbs";
     static  String LOCAL = "local";
     static  String  GCP = "gcp";
     static  String  TEST = "test";
     static  String  DEV = "dev";
     static  String PROD = "prod";
    static  String DEV_GCP = join(DEV, GCP);
    static  String PROD_GCP = join(PROD, GCP);
    static  String PROD_SBS = join(PROD, SBS);
    static  String DEV_SBS = join(DEV, SBS);
    static  String PROD_FSS = join(PROD, FSS);
    static  String DEV_FSS = join(DEV, FSS);
    static String NAIS_CLUSTER_NAME = "NAIS_CLUSTER_NAME";
    private static String join(String env, String cluster) {
        return env + "-" + cluster;
    }


}