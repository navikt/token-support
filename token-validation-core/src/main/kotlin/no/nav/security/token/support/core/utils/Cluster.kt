package no.nav.security.token.support.core.utils

import no.nav.security.token.support.core.utils.EnvUtil.NAIS_CLUSTER_NAME

enum class Cluster(private val navn : String) {
    TEST(EnvUtil.TEST),
    LOCAL(EnvUtil.LOCAL),
    DEV_SBS(EnvUtil.DEV_SBS),
    DEV_FSS(EnvUtil.DEV_FSS),
    DEV_GCP(EnvUtil.DEV_GCP),
    PROD_GCP(EnvUtil.PROD_GCP),
    PROD_FSS(EnvUtil.PROD_FSS),
    PROD_SBS(EnvUtil.PROD_SBS);

    companion object {

       @JvmStatic
        fun currentCluster() = entries.firstOrNull { it.navn == cluster() } ?: LOCAL

        @JvmStatic
        val isProd = cluster() in listOf(EnvUtil.PROD_GCP, EnvUtil.PROD_FSS)
        private fun cluster() = System.getenv(NAIS_CLUSTER_NAME)
    }
}