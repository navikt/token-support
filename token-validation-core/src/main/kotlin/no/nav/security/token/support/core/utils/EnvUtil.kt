package no.nav.security.token.support.core.utils

object EnvUtil {

    const val FSS = "fss"
    const val SBS = "sbs"
    const val LOCAL = "local"
    const val GCP = "gcp"
    const val TEST = "test"
    const val DEV = "dev"
    const val PROD = "prod"

    @JvmField
    val DEV_GCP = "$DEV-$GCP"

    @JvmField
    val PROD_GCP = "$PROD-$GCP"

    @JvmField
    val PROD_SBS = "$PROD-$SBS"

    @JvmField
    val DEV_SBS = "$DEV-$SBS"

    @JvmField
    val PROD_FSS = "$PROD-$FSS"

    @JvmField
    val DEV_FSS = "$DEV-$FSS"
    const val NAIS_CLUSTER_NAME = "NAIS_CLUSTER_NAME"
}