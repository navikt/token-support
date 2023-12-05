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
    val DEV_GCP = join(DEV, GCP)
    @JvmField
    val PROD_GCP = join(PROD, GCP)
    @JvmField
    val PROD_SBS = join(PROD, SBS)
    @JvmField
    val DEV_SBS = join(DEV, SBS)
    @JvmField
    val PROD_FSS = join(PROD, FSS)
    @JvmField
    val DEV_FSS = join(DEV, FSS)
    const val NAIS_CLUSTER_NAME = "NAIS_CLUSTER_NAME"

    private fun join(env : String, cluster : String) = "$env-$cluster"
}